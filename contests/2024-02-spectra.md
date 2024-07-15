# Spectra

The code under review can be found in [2024-02-spectra](https://github.com/code-423n4/2024-02-spectra).

## Findings Summary

| ID                                                                                                                                         | Title                                                        | Severity |
| ------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------ | -------- |
| [M-01](https://github.com/kazantseff/audits/blob/main/contests/2024-02-spectra.md#m-01-principaltoken-does-not-comply-with-eip5095)        | PrincipalToken does not comply with EIP5095                  | Medium   |
| [L-01](https://github.com/kazantseff/audits/blob/main/contests/2024-02-spectra.md#l-01-lack-of-minasset-check-in-claimyield-and-claimfees) | Lack of `minAsset` check in `claimYield()` and `claimFees()` | Low      |

## [M-01] PrincipalToken does not comply with EIP5095

### Vulnerability details

Principal Token contract is an ERC5095 vault that allows users to tokenize their yield in a permissionless manner.

> **Important** The [contest page](https://code4rena.com/audits/2024-02-spectra#top) explicitly states that PrincipalToken must conform with the EIP-5095.

The following specification of `redeem()` is taken directly from the EIP-5095:

> At or after maturity, burns exactly principalAmount of Principal Tokens from `from` and sends underlyingAmount of underlying tokens to `to`. MUST support a redeem flow where the Principal Tokens are burned from `holder` directly where `holder` is `msg.sender` or `msg.sender` has EIP-20 approval over the principal tokens of `holder`.

The following specification of withdraw() is taken directly from the EIP-5095:

> Burns `principalAmount` from `holder` and sends exactly `underlyingAmount` of underlying tokens to `receiver`. MUST support a withdraw flow where the principal tokens are burned from `holder` directly where `holder` is `msg.sender` or `msg.sender` has EIP-20 approval over the principal tokens of `holder`.

Both these functions should allow an approved user to redeem or withdraw approved Principal tokens, but currently, that's impossible. All `redeem` functions internally call [\_beforeRedeem()](https://github.com/code-423n4/2024-02-spectra/blob/383202d0b84985122fe1ba53cfbbb68f18ba3986/src/tokens/PrincipalToken.sol#L805-L821), which has this check in place:

```solidity
if (_owner != msg.sender) {
            revert UnauthorizedCaller();
    }
```

The same can be said about every `withdraw` function. All of them call [\_beforeWithdraw()](https://github.com/code-423n4/2024-02-spectra/blob/383202d0b84985122fe1ba53cfbbb68f18ba3986/src/tokens/PrincipalToken.sol#L828-L842), which has the same check in place.

As per EIP-5095 both `convertToUnderlying()` and `convertToPrincipal()` functions _MUST NOT revert unless due to integer overflow caused by an unreasonably large input_.
In case of `convertToUnderlying()` function, it calls [\_convertSharesToIBTs()](https://github.com/code-423n4/2024-02-spectra/blob/383202d0b84985122fe1ba53cfbbb68f18ba3986/src/tokens/PrincipalToken.sol#L659-L672), which can revert with `RateError` when `ibtRate` is 0.
In case of `convertToPrincipal()` function, it calls [\_convertIBTsToShares()](https://github.com/code-423n4/2024-02-spectra/blob/383202d0b84985122fe1ba53cfbbb68f18ba3986/src/tokens/PrincipalToken.sol#L680-L693), which can revert with `RateError` when `ptRate` is 0.

As per EIP-5095 `maxWithdraw()` must not revert, but it can revert because of `whenNotPausedModifier` or because of the `RateError` mentioned above.

### Impact

PrincipalToken contract does not respect the EIP standards it claims to follow. This breaks compatibility and violates invariants stated in the README.

### Recommended Mitigation

Ensure that PrincipalToken is EIP-compliant. Alternatively, document that some functions deviate from the ERC5095 specification.

## [L-01] Lack of `minAsset` check in `claimYield()` and `claimFees()`

### Vulnerability details

`claimFees()` function allows the fee collector set by the protocol to claim fees in IBT.
[PrincipalToken.sol#L329-L337](https://github.com/code-423n4/2024-02-spectra/blob/383202d0b84985122fe1ba53cfbbb68f18ba3986/src/tokens/PrincipalToken.sol#L329-L337)

```solidity
function claimFees() external override returns (uint256 assets) {
        if (msg.sender != IRegistry(registry).getFeeCollector()) {
            revert UnauthorizedCaller();
        }
        uint256 ibts = unclaimedFeesInIBT;
        unclaimedFeesInIBT = 0;
        assets = IERC4626(ibt).redeem(ibts, msg.sender, address(this));
        emit FeeClaimed(msg.sender, ibts, assets);
    }
```

`claimYield()` allows users to claim their yield in IBT.
[PrincipalToken.sol#L369-L374](https://github.com/code-423n4/2024-02-spectra/blob/383202d0b84985122fe1ba53cfbbb68f18ba3986/src/tokens/PrincipalToken.sol#L369-L374)

```solidity
function claimYield(address _receiver) public override returns (uint256 yieldInAsset) {
        uint256 yieldInIBT = _claimYield();
        if (yieldInIBT != 0) {
            yieldInAsset = IERC4626(ibt).redeem(yieldInIBT, _receiver, address(this));
        }
    }
```

As can be seen, both these functions redeem ibts from the ERC4626 vault, but they lack `minAssets` check. To protect users or feeCollector from receiving less assets for their amount of ibts, `minAssets` parameter should be used.

### Impact

The entire amount of ibts can be lost.

### Recommended Mitigation

[PrincipalToken.sol#L369-L374](https://github.com/code-423n4/2024-02-spectra/blob/383202d0b84985122fe1ba53cfbbb68f18ba3986/src/tokens/PrincipalToken.sol#L369-L374)

```diff
- function claimYield(address _receiver) public override returns (uint256 yieldInAsset) {
+ function claimYield(address _receiver, uint256 minAssets) public override returns (uint256 yieldInAsset) {
        uint256 yieldInIBT = _claimYield();
        if (yieldInIBT != 0) {
            yieldInAsset = IERC4626(ibt).redeem(yieldInIBT, _receiver, address(this));
+           require(yieldInAsset >= minAssets);
        }
    }
```

[PrincipalToken.sol#L329-L337](https://github.com/code-423n4/2024-02-spectra/blob/383202d0b84985122fe1ba53cfbbb68f18ba3986/src/tokens/PrincipalToken.sol#L329-L337)

```diff
- function claimFees() external override returns (uint256 assets) {
+ function claimFees(uint256 minAssets) external override returns (uint256 assets) {
        if (msg.sender != IRegistry(registry).getFeeCollector()) {
            revert UnauthorizedCaller();
        }
        uint256 ibts = unclaimedFeesInIBT;
        unclaimedFeesInIBT = 0;
        assets = IERC4626(ibt).redeem(ibts, msg.sender, address(this));
+       require(assets >= minAssets);
        emit FeeClaimed(msg.sender, ibts, assets);
    }

```
