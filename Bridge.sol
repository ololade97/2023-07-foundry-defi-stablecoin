// SPDX-License-Identifier: GPL-3.0-only

// ██████████████     ▐████▌     ██████████████
// ██████████████     ▐████▌     ██████████████
//               ▐████▌    ▐████▌
//               ▐████▌    ▐████▌
// ██████████████     ▐████▌     ██████████████
// ██████████████     ▐████▌     ██████████████
//               ▐████▌    ▐████▌
//               ▐████▌    ▐████▌
//               ▐████▌    ▐████▌
//               ▐████▌    ▐████▌
//               ▐████▌    ▐████▌
//               ▐████▌    ▐████▌

pragma solidity 0.8.17;

import "@keep-network/random-beacon/contracts/Governable.sol";
import "@keep-network/random-beacon/contracts/ReimbursementPool.sol";
import {IWalletOwner as EcdsaWalletOwner} from "@keep-network/ecdsa/contracts/api/IWalletOwner.sol";

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/utils/math/SafeCastUpgradeable.sol";

import "./IRelay.sol";
import "./BridgeState.sol";
import "./Deposit.sol";
import "./DepositSweep.sol";
import "./Redemption.sol";
import "./BitcoinTx.sol";
import "./EcdsaLib.sol";
import "./Wallets.sol";
import "./Fraud.sol";
import "./MovingFunds.sol";

import "../bank/IReceiveBalanceApproval.sol";
import "../bank/Bank.sol";

/// @title Bitcoin Bridge
/// @notice Bridge manages BTC deposit and redemption flow and is increasing and
///         decreasing balances in the Bank as a result of BTC deposit and
///         redemption operations performed by depositors and redeemers.
///
///         Depositors send BTC funds to the most recently created off-chain
///         ECDSA wallet of the bridge using pay-to-script-hash (P2SH) or
///         pay-to-witness-script-hash (P2WSH) containing hashed information
///         about the depositor's Ethereum address. Then, the depositor reveals
///         their Ethereum address along with their deposit blinding factor,
///         refund public key hash and refund locktime to the Bridge on Ethereum
///         chain. The off-chain ECDSA wallet listens for these sorts of
///         messages and when it gets one, it checks the Bitcoin network to make
///         sure the deposit lines up. If it does, the off-chain ECDSA wallet
///         may decide to pick the deposit transaction for sweeping, and when
///         the sweep operation is confirmed on the Bitcoin network, the ECDSA
///         wallet informs the Bridge about the sweep increasing appropriate
///         balances in the Bank.
/// @dev Bridge is an upgradeable component of the Bank. The order of
///      functionalities in this contract is: deposit, sweep, redemption,
///      moving funds, wallet lifecycle, frauds, parameters.
contract Bridge is
    Governable,
    EcdsaWalletOwner,
    Initializable,
    IReceiveBalanceApproval
{
    using BridgeState for BridgeState.Storage;
    using Deposit for BridgeState.Storage;
    using DepositSweep for BridgeState.Storage;
    using Redemption for BridgeState.Storage;
    using MovingFunds for BridgeState.Storage;
    using Wallets for BridgeState.Storage;
    using Fraud for BridgeState.Storage;

    BridgeState.Storage internal self;

    // ... existing code ...

    /// @notice Requests redemption of the given amount from the specified
    ///         wallet to the redeemer Bitcoin output script. Used by
    ///         `Bank.approveBalanceAndCall`. Can handle more complex cases
    ///         where balance owner may be someone else than the redeemer.
    ///         For example, vault redeeming its balance for some depositor.
    /// @param balanceOwner The address of the Bank balance owner whose balance
    ///        is getting redeemed.
    /// @param amount Requested amount in satoshi. This is also the Bank balance
    ///        that is taken from the `balanceOwner` upon request.
    ///        Once the request is handled, the actual amount of BTC locked
    ///        on the redeemer output script will be always lower than this value
    ///        since the treasury and Bitcoin transaction fees must be incurred.
    ///        The minimal amount satisfying the request can be computed as:
    ///        `amount - (amount / redemptionTreasuryFeeDivisor) - redemptionTxMaxFee`.
    ///        Fees values are taken at the moment of request creation.
    /// @param redemptionData ABI-encoded redemption data:
    ///        [
    ///          address redeemer,
    ///          bytes20 walletPubKeyHash,
    ///          bytes32 mainUtxoTxHash,
    ///          uint32 mainUtxoTxOutputIndex,
    ///          uint64 mainUtxoTxOutputValue,
    ///          bytes redeemerOutputScript
    ///        ]
    ///
    ///        - redeemer: The Ethereum address of the redeemer who will be able
    ///        to claim Bank balance if anything goes wrong during the redemption.
    ///        In the most basic case, when someone redeems their balance
    ///        from the Bank, `balanceOwner` is the same as `redeemer`.
    ///        However, when a Vault is redeeming part of its balance for some
    ///        redeemer address (for example, someone who has earlier deposited
    ///        into that Vault), `balanceOwner` is the Vault, and `redeemer` is
    ///        the address for which the vault is redeeming its balance to,
    ///        - walletPubKeyHash: The 20-byte wallet public key hash (computed
    ///        using Bitcoin HASH160 over the compressed ECDSA public key),
    ///        - mainUtxoTxHash: Data of the wallet's main UTXO TX hash, as
    ///        currently known on the Ethereum chain,
    ///        - mainUtxoTxOutputIndex: Data of the wallet's main UTXO output
    ///        index, as currently known on Ethereum chain,
    ///        - mainUtxoTxOutputValue: Data of the wallet's main UTXO output
    ///        value, as currently known on Ethereum chain,
    ///        - redeemerOutputScript The redeemer's length-prefixed output
    ///        script (P2PKH, P2WPKH, P2SH or P2WSH) that will be used to lock
    ///        redeemed BTC.
    /// @dev Requirements:
    ///      - The caller must be the Bank,
    ///      - Wallet behind `walletPubKeyHash` must be live,
    ///      - `mainUtxo` components must point to the recent main UTXO
    ///        of the given wallet, as currently known on the Ethereum chain,
    ///      - `redeemerOutputScript` must be a proper Bitcoin script,
    ///      - `redeemerOutputScript` cannot have wallet PKH as payload,
    ///      - `amount` must be above or equal the `redemptionDustThreshold`,
    ///      - Given `walletPubKeyHash` and `redeemerOutputScript` pair can be
    ///        used for only one pending request at the same time,
    ///      - Wallet must have enough Bitcoin balance to process the request.
    ///
    ///      Note on upgradeability:
    ///      Bridge is an upgradeable contract deployed behind
    ///      a TransparentUpgradeableProxy. Accepting redemption data as bytes
    ///      provides great flexibility. The Bridge is just like any other
    ///      contract with a balance approved in the Bank and can be upgraded
    ///      to another version without being bound to a particular interface
    ///      forever. This flexibility comes with the cost - developers
    ///      integrating their vaults and dApps with `Bridge` using
    ///      `approveBalanceAndCall` need to pay extra attention to
    ///      `redemptionData` and adjust the code in case the expected structure
    ///      of `redemptionData`  changes.
    function receiveBalanceApproval(
        address balanceOwner,
        uint256 amount,
        bytes calldata redemptionData
    ) external override {
        require(msg.sender == address(self.bank), "Caller is not the bank");

        self.requestRedemption(
            balanceOwner,
            SafeCastUpgradeable.toUint64(amount),
            redemptionData
        );
    }

    // ... rest of the contract code ...
}