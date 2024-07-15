# Ethereum Credit Guild

The code under review can be found in [2023-12-ethereumcreditguild](https://github.com/code-423n4/2023-12-ethereumcreditguild).

## Findings Summary

| ID       | Title                                                                                                                     | Severity |
| -------- | ------------------------------------------------------------------------------------------------------------------------- | -------- |
| [H-01]() | If a user increments gaugeWeight after notifyPnL and profit disitribution, he will receive rewards he is not entitled to. | High     |
| [H-02]() | If a after loss has occured user stakes his CREDIT in SurplusGuildMinter he will get unjustly slashed.                    | High     |
| [M-01]() | Guild token can only store one ProfitManager.                                                                             | Medium   |
| [M-02]() | There is no way to liquidate a position if it breaches maxDebtPerCollateralToken value creating bad debt.                 | Medium   |

## [H-01] If a user increments gaugeWeight after notifyPnL and profit disitribution, he will receive rewards he is not entitled to.

### Vulnerability details

The function `incrementGauge` allows user to vote for a particular term with their GUILD tokens:

```solidity
function incrementGauge(
        address gauge,
        uint256 weight
    ) public virtual returns (uint256 newUserWeight) {
        require(isGauge(gauge), "ERC20Gauges: invalid gauge");
        _incrementGaugeWeight(msg.sender, gauge, weight);
        return _incrementUserAndGlobalWeights(msg.sender, weight);
    }
```

User are able to vote for terms with their GUILD tokens to increment gauge weight of any particular term in the system. Gauge weight determines the maximum amount of debt that can be issued on a term. When there is profit in a term it is distributed through call to `ProfitManager.notifyPnL()`, which increases the profitIndex of a term.

```solidity
if (_gaugeWeight != 0) {
                    uint256 _gaugeProfitIndex = gaugeProfitIndex[gauge];
                    if (_gaugeProfitIndex == 0) {
                        _gaugeProfitIndex = 1e18;
                    }
                    gaugeProfitIndex[gauge] =
                        _gaugeProfitIndex +
                        (amountForGuild * 1e18) /
                        _gaugeWeight;
                }
```

Users will receive rewards if they have been voting for a term with their GUILD.
In order to claim rewards, a user has to call `ProftiManager.claimGaugeRewards()`:

```solidity
function claimGaugeRewards(
        address user,
        address gauge
    ) public returns (uint256 creditEarned) {
        uint256 _userGaugeWeight = uint256(
            GuildToken(guild).getUserGaugeWeight(user, gauge)
        );
        if (_userGaugeWeight == 0) {
            return 0;
        }
        uint256 _gaugeProfitIndex = gaugeProfitIndex[gauge];
        uint256 _userGaugeProfitIndex = userGaugeProfitIndex[user][gauge];
        if (_gaugeProfitIndex == 0) {
            _gaugeProfitIndex = 1e18;
        }
        if (_userGaugeProfitIndex == 0) {
            _userGaugeProfitIndex = 1e18;
        }
        uint256 deltaIndex = _gaugeProfitIndex - _userGaugeProfitIndex;
        if (deltaIndex != 0) {
            creditEarned = (_userGaugeWeight * deltaIndex) / 1e18;
            userGaugeProfitIndex[user][gauge] = _gaugeProfitIndex;
        }
        if (creditEarned != 0) {
            emit ClaimRewards(block.timestamp, user, gauge, creditEarned);
            CreditToken(credit).transfer(user, creditEarned);
        }
    }
```

This function determines the amount of rewards you should receive based on delta of gaugeProfitIndex and userGaugeProfitIndex.
The problem lies in a way userGaugeProfitIndex is updated for a user. If userGaugeProfitIndex is 0, it will be set to 1e18, which allows any user to receive rewards even after they were distributed in `notifyPnL()`.

Imagine a scenario:

- Alice increments term's weight by 10_000.
- `notifyPnL()` is called with a profit of 10_000.
- gaugeProfitIndex is set to 1.5e18, assuming 50% split is set between GUILD and CREDIT.
- maliciousUser increments term's weight by 10_000.
- maliciousUser's profitIndex is 0 at this point.
- Now maliciousUser calls `claimGaugeRewards()`, because his profitIndex is 0, it is set to 1e18 in `claimGaugeRewards()`.
- Now the delta is 0.5e18 and maliciousUser receives 5000 CREDIT.
- Alice calls `claimGaugeRewards()`, but transaction reverts, since maliciousUser already claimed all of the rewards.

This is essentially a risk-free activity, as maliciousUser is not risking his GUILD tokens to get slashed, while claiming rewards of fair users.

### Impact

Attacker is able to steal all rewards.

### Proof Of Concept

```solidity
function testIncrementWeightAfterProfitDistribution() public {
        vm.startPrank(governor);
        core.grantRole(CoreRoles.GOVERNOR, address(this));
        core.grantRole(CoreRoles.CREDIT_MINTER, address(this));
        core.grantRole(CoreRoles.GUILD_MINTER, address(this));
        core.grantRole(CoreRoles.GAUGE_ADD, address(this));
        core.grantRole(CoreRoles.GAUGE_PARAMETERS, address(this));
        core.grantRole(CoreRoles.GAUGE_PNL_NOTIFIER, address(this));
        vm.stopPrank();

        vm.prank(governor);
        profitManager.setProfitSharingConfig(
            0, // surplusBufferSplit
            0.5e18, // creditSplit
            0.5e18, // guildSplit
            0, // otherSplit
            address(0) // otherRecipient
        );
        guild.setMaxGauges(1);
        guild.addGauge(1, gauge1);

        address maliciousUser = makeAddr("maliciousUser");

        // Have a user voting for a gauge before the profit distribution
        address user = makeAddr("user");
        guild.mint(user, 10000e18);
        vm.prank(user);
        guild.incrementGauge(address(gauge1), 10000e18);

        uint256 profitIndex = profitManager.gaugeProfitIndex(address(gauge1));
        assertEq(profitIndex, 0);

        credit.mint(address(profitManager), 10000e18);
        profitManager.notifyPnL(address(gauge1), 10000e18);

        // New profit index signaling that profits were distributed
        uint256 newProfitIndex = profitManager.gaugeProfitIndex(
            address(gauge1)
        );
        assertEq(newProfitIndex, 1500000000000000000);

        // @audit User started voting for a gauge only after profit was distributed
        guild.mint(maliciousUser, 10000e18);
        vm.prank(maliciousUser);
        guild.incrementGauge(address(gauge1), 10000e18);
        // User gaugeProfitIndex is 0
        uint256 index = profitManager.userGaugeProfitIndex(
            maliciousUser,
            address(gauge1)
        );
        assertEq(index, 0);

        // @audit maliciousUser received all rewards in CREDIT
        uint256 balanceBefore = credit.balanceOf(maliciousUser);
        profitManager.claimGaugeRewards(maliciousUser, address(gauge1));
        uint256 balanceAfter = credit.balanceOf(maliciousUser);
        assertEq(balanceAfter, balanceBefore + 5000000000000000000000);

        // The first user staking did not receive anything
        vm.expectRevert();
        profitManager.claimGaugeRewards(user, address(gauge1));

        vm.prank(maliciousUser);
        guild.decrementGauge(address(gauge1), 10000e18);
        assertEq(guild.balanceOf(maliciousUser), 10000e18);
    }
```

### Recommended Mitigation Steps

The solution is to set the userGaugeProfitIndex to be equal to current gaugeProfitIndex at the time of calling `incrementGauge()`. This way user will receive rewards only if he was voting before profit distribution.

## [H-02] If a after loss has occured user stakes his CREDIT in SurplusGuildMinter he will get unjustly slashed.

### Vulnerability details

Anyone can stake CREDIT tokens in SGM to start voting in a gauge.
This allows outside participation of first loss capital and allows users to participate in the gauge system without exposure to GUILD token price. If the GUILD minted against CREDIT tokens is slashed while voting in a gauge, that CREDIT is seized and donated to the surplus buffer befor computing losses.

This is a part of `SurplusGuildMinter.getRewards()` function:

```solidity
if (lastGaugeLoss > uint256(userStake.lastGaugeLoss)) {
            slashed = true;
}

if (slashed) {
            emit Unstake(block.timestamp, term, uint256(userStake.credit));
            userStake = UserStake({
                stakeTime: uint48(0),
                lastGaugeLoss: uint48(0),
                profitIndex: uint160(0),
                credit: uint128(0),
                guild: uint128(0)
            });
            updateState = true;
}
```

If a new loss occured in a gauge user was voting for, he will get slashed and his CREDIT is seized. This should only be true for a loss that occured after user has started staking, but currently due to an error in the code, user will get slashed even if the loss occured before he started staking. The reasons for this is in `getRewards()` function:

```solidity
lastGaugeLoss = GuildToken(guild).lastGaugeLoss(term);
        if (lastGaugeLoss > uint256(userStake.lastGaugeLoss)) {
            slashed = true;
        }

        // if the user is not staking, do nothing
        userStake = _stakes[user][term];
```

As you can see in the first check that determines if a user should get slashed, userStake is not yet defined, meaning `lastGaugeLoss` will always be greater than `userStake.lastGaugeLoss`, since latter is always 0 at this point. If there was at least one loss and lastGaugeLoss is not 0, every user to start staking after will get slashed.

### Impact

The impact is a direct loss of funds without a way to avoid this.

### Proof Of Concept

```solidity
function testStakeAfterLoss() public {
        address alice = makeAddr("alice");
        credit.mint(alice, 100e18);
        vm.startPrank(alice);
        credit.approve(address(sgm), 100e18);
        sgm.stake(term, 100e18);
        vm.stopPrank();

        credit.mint(address(profitManager), 35e18);
        profitManager.notifyPnL(term, 35e18);

        vm.warp(block.timestamp + 13);
        vm.roll(block.number + 1);

        // loss in gauge
        profitManager.notifyPnL(term, -27.5e18);

        vm.warp(block.timestamp + 13);
        vm.roll(block.number + 1);

        guild.applyGaugeLoss(term, address(sgm));

        address bob = makeAddr("bob");
        credit.mint(bob, 50e18);
        vm.startPrank(bob);
        credit.approve(address(sgm), 50e18);
        // Bob stakes after a loss
        sgm.stake(term, 50e18);
        assertEq(profitManager.termSurplusBuffer(term), 50e18);
        // Right after bob staked, he is immediately slashed
        (, , bool slashed) = sgm.getRewards(bob, term);
        assertEq(slashed, true);
        sgm.unstake(term, 50e18);
        vm.stopPrank();
        // When he unstakes, he does not receive his CREDIT
        assertEq(credit.balanceOf(bob), 0);
}
```

### Recommended Mitigation Steps

In `getRewards()` function read `userStake` from state before checking if `lastGaugeLoss` is greater than `userStake.lastGaugeLoss`.

```solidity
lastGaugeLoss = GuildToken(guild).lastGaugeLoss(term);
// if the user is not staking, do nothing
userStake = _stakes[user][term]; <----- @audit
if (lastGaugeLoss > uint256(userStake.lastGaugeLoss)) {
    slashed = true;
}
```

## [M-01] Guild token can only store one ProfitManager.

### Vulnerability details

The GUILD is a governance token deployed for the protocol. There could exist multiple markets, each requiring its own:

- Credit token
- PSM
- ProfitManager
- RateLimitedMinter

ProfitManager exists to track profits accross multiple LendingTerms in a market. For example in USDC makret, there will be one CREDIT token, i.e gUSDC, which will have its own PSM and RateLimitedMinter. Profit manager in USDC market will track profits accross mulitpler LendingTerms, which will offer borrowers gUSDC, each with their own parameters. Currently GUILD token can only store a reference to only 1 ProfitManager, which means that there is no way to deploy more than one market.

### Impact

The impact is the protocol is limited in its own functionality without a way to create new markets.

### Proof Of Concept

```solidity
contract GuildToken is CoreRef, ERC20Burnable, ERC20Gauges, ERC20MultiVotes {
    using EnumerableSet for EnumerableSet.AddressSet;

    /// @notice reference to ProfitManager
    address public profitManager;
```

### Recommended Mitigation Steps

Modify GUILD token contract so it does not store a reference to a profit manager but rather uses gauge's ProfitManager, i.e:

```solidity
ProfitManager(LendingTerm(gauge).profitManager()).claimGaugeRewards(user, gauge);
```

## [M-02] There is no way to liquidate a position if it breaches maxDebtPerCollateralToken value creating bad debt.

### Vulnerability details

Liquidations in the system are done via `LendingTerm._call()`, which will auction the loan's collateral to repay outstanding debt. A loan can be called only if the term has been offboarded or if a loan missed a periodic partialRepay.
To understand the issue, we must understand how the loan is created and how it can be called.
First, when a loan is created through a call to `_borrow()`, the contract checks if the borrowAmount is lesser than the maxBorrow:

```solidity
uint256 maxBorrow = (collateralAmount * params.maxDebtPerCollateralToken) / creditMultiplier;
 require(
            borrowAmount <= maxBorrow,
            "LendingTerm: not enough collateral"
        );
```

It calcualates maxBorrow using `params.maxDebtPerCollateralToken`. For example, if maxDebtPerCollateralToken is 2000e18, then with 15e18 tokens of collateral, a user can borrow up to 30_000 of CREDIT tokens.

Then it's important to understand how liquidations work in the system. If we were to look at `_call()` function we could notice that it only allows liquidations in two specific cases:

```solidity
require(
            GuildToken(refs.guildToken).isDeprecatedGauge(address(this)) ||
                partialRepayDelayPassed(loanId),
            "LendingTerm: cannot call"
        );
```

It will only allow to call a position if a term is depreceated or if the loan missed a periodic partial repayment.
This approach creates problems and opens up a griefing attack vector.

There are few ways it can go wrong. Let's firstly discuss an issue that will arise even for a non-malicious user.
In order for a user to not get liquidated, he must call `partialRepay()` before a specific deadline set in term's parameters. If we look at the `_partialRepay()` function:

```solidity
require(
            debtToRepay >= (loanDebt * params.minPartialRepayPercent) / 1e18,
            "LendingTerm: repay below min"
        );
```

We can see, that it enforces user to repay at least `params.minPartialRepayPercent`, which may not always be enough for a position to stay "healthy". By "healthy" I mean a position that does not breach `maxDebtPerCollateralToken` value, which is a parameter of a LendingTerm.

Imagine a scenario:

- Interest rate = 15%
- minPartialRepayPercent = 10%
- maxDebtPerCollateralToken = 2000

User borrows 30_000 CREDIT with 15 TOKENS of collateral. His debtPerCollateral value is `30_000 / 15 = 2000`, which is exactly equal to maxDebtPerCollateralToken.
Now a year has passed, the loanDebt (debt + interest) is 34_500, a user is obligated to repay at least `34_500 * 0.1 = 3450`. After partial repayment his debtPerCollateral value is `(34500 - 3450) / 15 = 2070`. While he breached the maxDebtPerCollateralToken value, his position is not callable, because he did not miss a periodic partial repayment.

> Also it's worth noting, that currently even if a user missed a periodic partial repayment, he can still make a call to `partialRepay()` if his position was not yet called. Becuase of this, it will be easire for such situation to occur, since the interest will be accruing and when a user finally calls `partialRepay()` he is still only obligated to repay at least minPartialRepayPercent for a position that went even deeper underwater.So currently due to a combination of multiple factors, bad debt can essentially occur and it will be impossible to liquidate such position without offboarding a term.

Now let's talk about a potential malicious behaviour that is encouraged in the current implementation.
Periodic partial repayments are not enforced for every term, they may or may not be enabled, so the only condition for a liquidation in this case is a depreceated term.
This means that basically every position is essentially "unliquitable", because `partialRepayDelayPassed()` will always return false in such case:

```solidity
function partialRepayDelayPassed(
        bytes32 loanId
    ) public view returns (bool) {
        // if no periodic partial repays are expected, always return false
        if (params.maxDelayBetweenPartialRepay == 0) return false;
```

A malicious user can abuse this by not repaying his loan or by not adding collateral to his loan when interest accrues above maxDebtPerCollateralToken.
There will be no way to do anything with such positions, the only possible solution would be to offboard a full term. This will obviously damage the protocol, as offboarding a term means calling every position, which subsequently increases a chance of a loss occuring. Also by offboarding a term, lenders will miss out on interest, because every position is force-closed.

> The current plan of the protocol was to have partialRepay of at least interestRate every year, so that positions do not grow into insolvent territory. It's hard and unreasonable to know every set of parameters that can lead to debtPerCollateral being greater than maxDebtPerCollateralToken even after partialRepay. After a discussion with the sponsor, it was said that ultimately the protocol team will not be the only one to deploy new terms, so it's better to enforce a proper liquidation flow in the contract.

### Impact

Inability to liquidate unhealthy positions potentially leading to occurrence of bad debt.

### Proof Of Concept

Here is the PoC demonstrating this issue, for the sake of simplicity I did not change the protocol's test suite configuration, but I just wanted to show that this is possible with any parameters (even the ones expected by the team), because a loan can still be partially repaid even if it missed partial repay deadline (I mention this earlier in my report, saying that this is the reason that makes this situation even easier to occur).

```solidity
function testBreakMaxDebtPerCollateralToken() public {
        // prepare
        uint256 borrowAmount = 30_000e18;
        uint256 collateralAmount = 15e18;
        collateral.mint(address(this), collateralAmount);
        collateral.approve(address(term), collateralAmount);
        credit.approve(address(term), type(uint256).max);

        // borrow
        bytes32 loanId = term.borrow(borrowAmount, collateralAmount);
        vm.warp(block.timestamp + (term.YEAR() * 3));
        // 3 years have passed, and now position's debt is 39_000
        uint256 loanDebt = term.getLoanDebt(loanId);
        assertEq(loanDebt, 39_000e18);
        // A user is able to call partialRepays even if he missed partialRepays deadline
        term.partialRepay(
            loanId,
            (loanDebt * _MIN_PARTIAL_REPAY_PERCENT) / 1e18
        );
        // After repaying just minPartialRepayPercent, a debtPerCollateralToken of the position is 2080, which is greater than maxDebtPerCollateral
        uint256 newLoanDebt = term.getLoanDebt(loanId);
        assertEq((newLoanDebt / 15e18) * 1e18, 2080000000000000000000);
        assertGt((newLoanDebt / 15e18) * 1e18, _CREDIT_PER_COLLATERAL_TOKEN);

        // A position cannot be called
        vm.expectRevert("LendingTerm: cannot call");
        term.call(loanId);
    }
```

In conclusion I want to say that parameters of a LendingTerm are only limited to a logical sort of degree, i.e:

- interest rate can be anything from 0 to 100%
- maxDelayBetweenPartialRepay can be anything from 0 to 1 year
- minPartialRepayPercent can be anything from 0 to 100%

Because of this the situation is bound to occur. It's better to enforce strict rules on the smart contract level.

### Recommended Mitigation Steps

Allows loans above `maxDebtPerCollateral` to be liquidatable.

The potential way to modify `_call()` function:

```solidity
require(
    GuildToken(refs.guildToken).isDeprecatedGauge(address(this)) ||
        partialRepayDelayPassed(loanId) ||
        loan.debtPerCollateralToken > params.maxDebtPerCollateral,
    "LendingTerm: cannot call"
);
```
