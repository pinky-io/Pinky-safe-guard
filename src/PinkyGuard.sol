// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "@safe-contracts/contracts/common/Enum.sol";
import "@safe-contracts/contracts/base/GuardManager.sol";
import "@safe-contracts/contracts/Safe.sol";
import "@safe-contracts/contracts/interfaces/IERC165.sol";

import "./Utils.sol";

interface IERC721 {
    function ownerOf(uint256 tokenId) external view returns (address owner);
}

contract PinkyGuard is IERC165, BaseGuard {
    address public immutable safe; // Address of the user Smart Contract Wallet
    address public immutable marketplace; // Address of the marketplace

    // Data for one Borrow
    struct Borrow {
        address nftContract;
        uint256 NftTokenId;
    }

    // List of current borrowed NFTs
    Borrow[] public BorrowedNfts;
    mapping(bytes32 => uint256) public BorrowIdMapping;

    modifier marketplaceOnly(address caller) {
        require(msg.sender == marketplace, "Reserved to marketplace");
        _;
    }

    constructor(address _safe, address _marketplace) {
        safe = _safe;
        marketplace = _marketplace;
    }

    function checkTransaction(
        address to,
        uint256 value,
        bytes memory data,
        Enum.Operation operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address payable refundReceiver,
        bytes memory signatures,
        address msgSender
    ) external override {
        // User cannot set approval for borrowed tokens
        require(!IsApproval(data), "You are not allowed to set approval for token");
        // User cannot setup another guard
        require(!IsSetGuard(data), "You are not allowed to setup another guard");
    }

    function checkAfterExecution(bytes32 txHash, bool success) external override {
        // Revert if the NFT isn't in the wallet at the end of the transaction
        for (uint256 i = 0; i < BorrowedNfts.length; i++) {
            require(
                safe == IERC721(BorrowedNfts[i].nftContract).ownerOf(BorrowedNfts[i].NftTokenId),
                "You are not allowed to transfer the NFT"
            );
        }
    }

    function IsSetGuard(bytes memory data) internal pure returns (bool) {
        bytes4 ExpectedSetGuardFunctionSelector = bytes4(keccak256("setGuard(address)"));

        // If transaction data is shorter than 4 bytes it is not a setGuard transaction
        if (data.length < 4) {
            return false;
        }

        // Get the function selector
        bytes4 ActualFunctionSelector;
        assembly {
            ActualFunctionSelector := mload(add(data, 32))
        }

        // Check if function selector corresponds to the setGuard function
        return ActualFunctionSelector == ExpectedSetGuardFunctionSelector;
    }

    function IsApproval(bytes memory data) internal view returns (bool result) {
        result = false;
        bytes4 ExpectedApproveFunctionSelector = bytes4(keccak256("approve(address,uint256)"));
        bytes4 ExpectedSetApprovalForAllFunctionSelector = bytes4(keccak256("setApprovalForAll(address,bool)"));

        // If transaction data is shorter than 4 bytes it is not an approval transaction
        if (data.length < 4) {
            return false;
        }

        // Get the function selector
        bytes4 ActualFunctionSelector;
        assembly {
            ActualFunctionSelector := mload(add(data, 32))
        }

        // If the function called in the transaction is Approve then check if it concerns the currently borrowed NFTs
        if (ActualFunctionSelector == ExpectedApproveFunctionSelector) {
            // Decode the transaction data to get the Smart Contract address and NFT token ID
            (address ActualAddress, uint256 ActualId) =
                abi.decode(Utils.slice(data, 4, data.length - 4), (address, uint256));

            for (uint256 i = 0; i < BorrowedNfts.length; i++) {
                // If the transaction concerns any currently borrowed NFT we need to revert
                if ((ActualAddress == BorrowedNfts[i].nftContract) && (ActualId == BorrowedNfts[i].NftTokenId)) {
                    return true;
                }
            }
        } else if (ActualFunctionSelector == ExpectedSetApprovalForAllFunctionSelector) {
            // If the function called in the transaction is setApproveForAll
            // then check if it concerns the collection of currently borrowed NFTs

            // Decode the transaction data to get the Smart Contract address
            (address ActualAddress, bool ApprovalBool) =
                abi.decode(Utils.slice(data, 4, data.length - 4), (address, bool));
            for (uint256 i = 0; i < BorrowedNfts.length; i++) {
                if (ActualAddress == BorrowedNfts[i].nftContract) {
                    // If the transaction concerns the collection of currently borrowed NFT we need to revert
                    return true;
                }
            }
        }

        // Otherwise, the transaction can go on
        return false;
    }

    // Add a borrowed NFT to the Guard's list
    function addRent(address nftContract, uint256 _NftTokenId) external marketplaceOnly(msg.sender) {
        BorrowedNfts.push(Borrow(nftContract, _NftTokenId));
        BorrowIdMapping[Utils.hash(nftContract, _NftTokenId)] = BorrowedNfts.length - 1;
    }

    // Remove a borrowed NFT to the Guard's list
    // We perform a swap & delete operation with the last item of the list
    function deleteRent(address nftContract, uint256 _NftTokenId) external marketplaceOnly(msg.sender) {
        bytes32 HashToDelete = Utils.hash(nftContract, _NftTokenId);
        uint256 BorrowIdToDelete = BorrowIdMapping[HashToDelete];

        delete BorrowIdMapping[HashToDelete];

        BorrowedNfts[BorrowIdToDelete] = BorrowedNfts[BorrowedNfts.length - 1];
        BorrowedNfts.pop();

        bytes32 BorrowId2 =
            Utils.hash(BorrowedNfts[BorrowIdToDelete].nftContract, BorrowedNfts[BorrowIdToDelete].NftTokenId);
        BorrowIdMapping[BorrowId2] = BorrowIdToDelete;
    }

    function supportsInterface(bytes4 interfaceId) external view virtual override(IERC165, BaseGuard) returns (bool) {
        return interfaceId == 0x9a9d78ed // type(PinkyGuard).interfaceId
            || interfaceId == type(Guard).interfaceId // 0xe6d7a83a
            || interfaceId == type(IERC165).interfaceId; // 0x01ffc9a7
    }
}
