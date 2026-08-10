// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "./ParseBTCLib.sol";
import "./BytesLib.sol";
import "./BTCUtils.sol";

/**
 * @dev External library version of AuroraHelper + ParseBTCLib wrappers.
 *      Used by AuroraFullTestnet to keep that contract under the 24KB limit.
 *      All functions are public so they are deployed as a separate library
 *      and called via DELEGATECALL, not inlined.
 */
library AuroraHelperExt {

    /// @dev Computes an ordered binary Merkle root in external library code so
    ///      the Sepolia Aurora artifact can keep its deployment bytecode small.
    ///      The caller supplies a power-of-two leaf-node array.
    function registrationMerkleRoot(bytes32[] memory level) public pure returns (bytes32) {
        require(level.length > 0 && (level.length & (level.length - 1)) == 0, "FR0");
        uint256 width = level.length;
        while (width > 1) {
            for (uint256 i = 0; i < width; i += 2) {
                level[i / 2] = keccak256(abi.encodePacked(level[i], level[i + 1]));
            }
            width /= 2;
        }
        return level[0];
    }

    // -- ParseBTCLib wrappers ---------------------------------------------------

    function getTimelock(bytes memory txBytes) public pure returns (bytes4) {
        return ParseBTCLib.getTimelock(txBytes);
    }

    function getTxTimelock(bytes memory txBytes) public pure returns (uint32) {
        return ParseBTCLib.getTxTimelock(txBytes);
    }

    function getInputsData(bytes memory txBytes) public pure returns (ParseBTCLib.Input memory) {
        return ParseBTCLib.getInputsData(txBytes);
    }

    function getOutputsDataLNB(bytes memory txBytes)
        public pure
        returns (ParseBTCLib.HTLCData memory, ParseBTCLib.P2PKHData memory, ParseBTCLib.OpReturnData memory)
    {
        return ParseBTCLib.getOutputsDataLNB(txBytes);
    }

    // -- AuroraHelper functions ------------------------------------------------

    function checkTxAreWellFormed(
        bytes memory TxP,
        bytes memory TxV,
        bytes memory fundingTx_script,
        bytes32 fundingTxId
    ) public pure returns (
        ParseBTCLib.HTLCData[2] memory,
        ParseBTCLib.P2PKHData[2] memory,
        ParseBTCLib.OpReturnData memory
    ) {
        ParseBTCLib.HTLCData[2] memory lightningHTLC;
        ParseBTCLib.P2PKHData[2] memory p2pkh;
        ParseBTCLib.OpReturnData memory opreturn;
        (lightningHTLC[0], p2pkh[0], opreturn) = ParseBTCLib.getOutputsDataLNB(TxP);
        (lightningHTLC[1], p2pkh[1]) = ParseBTCLib.getOutputsDataLN(TxV);

        require(opreturn.data == lightningHTLC[1].rev_secret, "F0");
        require(p2pkh[0].value == lightningHTLC[1].value, "F1");
        require(lightningHTLC[0].value == p2pkh[1].value, "F2");

        (bytes memory pk1, bytes memory pk2) = ParseBTCLib.extractCompressedPK(fundingTx_script);
        require(sha256(BTCUtils.hash160(pk2)) == sha256(abi.encodePacked(p2pkh[0].pkhash)), "F3");
        require(sha256(BTCUtils.hash160(pk1)) == sha256(abi.encodePacked(p2pkh[1].pkhash)), "F4");

        require(ParseBTCLib.getInputsData(TxP).txid == fundingTxId, "F5");
        require(ParseBTCLib.getInputsData(TxV).txid == fundingTxId, "F6");

        return (lightningHTLC, p2pkh, opreturn);
    }

    function getRevSecret(bytes memory Tx) public pure returns (bytes32) {
        ParseBTCLib.HTLCData memory lightningHTLC;
        ParseBTCLib.P2PKHData memory p2pkh;
        ParseBTCLib.OpReturnData memory opreturn;
        (lightningHTLC, p2pkh, opreturn) = ParseBTCLib.getOutputsDataLNB(Tx);
        return lightningHTLC.rev_secret;
    }

    function checkSignaturesEcrecover(
        bytes memory TxP,
        bytes memory TxV,
        bytes memory fundingTx_script,
        bytes memory sighash,
        bytes memory pkProver_Uncompressed,
        bytes memory pkVerifier_Uncompressed
    ) public pure returns (bool) {
        ParseBTCLib.Signature[2] memory sig;
        sig[1] = ParseBTCLib.getSignature(TxP);
        sig[0] = ParseBTCLib.getSignature(TxV);

        bytes32[2] memory digest;
        digest[0] = ParseBTCLib.getTxDigest(TxP, fundingTx_script, sighash);
        address ethAddressV = ecrecover(digest[0], sig[1].v, bytes32(sig[1].r), bytes32(sig[1].s));
        address pkToAddressV = address(bytes20(BytesLib.slice(abi.encodePacked(keccak256(pkVerifier_Uncompressed)), 12, 20)));
        if (ethAddressV != pkToAddressV) {
            ethAddressV = ecrecover(digest[0], sig[1].v + 1, bytes32(sig[1].r), bytes32(sig[1].s));
            require(ethAddressV == pkToAddressV, "F7");
        }

        digest[1] = ParseBTCLib.getTxDigest(TxV, fundingTx_script, sighash);
        address ethAddressP = ecrecover(digest[1], sig[0].v, bytes32(sig[0].r), bytes32(sig[0].s));
        address pkToAddressP = address(bytes20(BytesLib.slice(abi.encodePacked(keccak256(pkProver_Uncompressed)), 12, 20)));
        if (ethAddressP != pkToAddressP) {
            ethAddressP = ecrecover(digest[1], sig[0].v + 1, bytes32(sig[0].r), bytes32(sig[0].s));
            require(ethAddressP == pkToAddressP, "F8");
        }

        return true;
    }

    function checkSignatureEcrecover(
        bytes memory Tx,
        bytes memory fundingTx_script,
        bytes memory sighash,
        bytes memory pk
    ) public pure {
        ParseBTCLib.Signature memory sigV = ParseBTCLib.getSignature(Tx);
        bytes32 digest = ParseBTCLib.getTxDigest(Tx, fundingTx_script, sighash);

        address ethAddress = ecrecover(digest, sigV.v, bytes32(sigV.r), bytes32(sigV.s));
        address pkToAddress = address(bytes20(BytesLib.slice(abi.encodePacked(keccak256(pk)), 12, 20)));
        if (ethAddress != pkToAddress) {
            ethAddress = ecrecover(digest, sigV.v + 1, bytes32(sigV.r), bytes32(sigV.s));
            require(ethAddress == pkToAddress, "F9");
        }
    }
}

