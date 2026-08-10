// SPDX-License-Identifier: MIT
pragma solidity ^0.8.9;

/**
 * @title AuroraFactory
 * @dev Deploys minimal EIP-1167 proxy clones of AuroraFull (the initializable
 *      implementation).  Each clone costs ~45,000 gas and delegates all calls
 *      to the shared implementation via DELEGATECALL, so each instance retains
 *      its own independent storage (prover, verifier, currentMerkleRoot, ...).
 *
 * Replay-resistance (Theorem 3) is preserved: each clone has a unique
 * address(this), so the per-contract leaf-index space is disjoint across batches.
 */
contract AuroraFactory {

    address public immutable implementation;
    address[] public batches;

    event BatchCreated(address indexed batch, uint256 indexed index);

    constructor(address _implementation) {
        require(_implementation != address(0), "Zero implementation");
        implementation = _implementation;
    }

    /**
     * @dev Deploy a new EIP-1167 minimal proxy clone and initialise it.
     * @param _prover  Prover address for this batch instance.
     * @param _verifier Verifier address for this batch instance.
     * @return batch   Address of the newly-deployed clone.
     */
    function createBatch(address _prover, address _verifier)
        external
        returns (address batch)
    {
        batch = _clone(implementation);
        // Call initialize() on the fresh clone
        (bool ok, bytes memory err) = batch.call(
            abi.encodeWithSignature("initialize(address,address)", _prover, _verifier)
        );
        require(ok, string(err));

        batches.push(batch);
        emit BatchCreated(batch, batches.length - 1);
    }

    /// @return The number of batch instances deployed via this factory.
    function batchCount() external view returns (uint256) {
        return batches.length;
    }

    // ---------------------------------------------------------------
    // EIP-1167 minimal proxy deployment (inlined - no OZ dependency)
    // ---------------------------------------------------------------
    function _clone(address target) internal returns (address result) {
        // Minimal proxy init code:
        // 3d602d80600a3d3981f3  - copy runtime code to memory
        // 363d3d373d3d3d363d73  - runtime: CALLDATACOPY setup
        // <20-byte target addr>
        // 5af43d82803e903d91602b57fd5bf3
        bytes20 targetBytes = bytes20(target);
        assembly {
            let clone := mload(0x40)
            mstore(clone,
                0x3d602d80600a3d3981f3363d3d373d3d3d363d73000000000000000000000000)
            mstore(add(clone, 0x14), targetBytes)
            mstore(add(clone, 0x28),
                0x5af43d82803e903d91602b57fd5bf30000000000000000000000000000000000)
            result := create(0, clone, 0x37)
        }
        require(result != address(0), "Clone deployment failed");
    }
}

