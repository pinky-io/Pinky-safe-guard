// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";

import "../src/PinkyGuard.sol";

contract PinkyGuardTest is Test {
    // for erc165 implementation purpose
    function testCalculateSelector() public view returns (bytes4) {
        PinkyGuard guard;

        return guard.BorrowIdMapping.selector ^ guard.BorrowedNfts.selector ^ guard.addRent.selector
            ^ guard.checkAfterExecution.selector ^ guard.checkTransaction.selector ^ guard.deleteRent.selector
            ^ guard.marketplace.selector ^ guard.safe.selector ^ guard.supportsInterface.selector;
    }
}
