// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

/**
 * @title MerkleTree
 * @dev A contract for verifying caller whitelist using a Merkle tree.
 */
contract MerkleTree {
    bytes32 public merkleRoot;

    /**
     * @dev Initializes the MerkleTree contract with the provided merkle root.
     * @param _merkleRoot The merkle root hash to be set.
     */
    constructor(bytes32 _merkleRoot) {
        merkleRoot = _merkleRoot;
    }

    /**
     * @dev Checks if the caller is whitelisted based on the provided proof and maximum allowance to mint.
     * @param proof The merkle proof.
     * @param maxAllowanceToMint The maximum allowance to mint for the caller.
     * @return A boolean indicating whether the caller is verified and whitelisted.
     */
    function checkInWhitelist(bytes32[] calldata proof, uint64 maxAllowanceToMint) public view returns (bool) {
        bytes32 leaf = keccak256(abi.encode(msg.sender, maxAllowanceToMint));
        bool verified = MerkleProof.verify(proof, merkleRoot, leaf);
        return verified;
    }
}