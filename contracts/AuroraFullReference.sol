// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "./AuroraFull.sol";

/// @notice Correctness oracle for R2 benchmarks.  It preserves AuroraFull's
/// registration and settlement semantics, but reconstructs the complete
/// registration-indexed Merkle tree at submission rather than using its
/// incremental frontier.  It is not the production deployment candidate.
contract AuroraFullReference is AuroraFull {
    function _rootForSubmission(uint256 padded) internal view override returns (bytes32) {
        return _registrationMerkleRoot(padded);
    }
}
