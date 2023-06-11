# Robocop Audit report Report for https://github.com/lidofinance/lido-dao
## File Analyzed: WithdrawalQueue.sol
 ## Summary

* The contract defines an interface for a liquid staking pool (IStETH) and a wrapper for it (IWstETH)
* It inherits from WithdrawalQueueBase which implements a queue for withdrawal requests 
* It uses OpenZeppelin's AccessControlEnumerable for access control and PausableUntil for pausing functionality
* It stores the stETH and wstETH token addresses as immutable variables 
* It has constants for the minimum and maximum stETH withdrawal amounts 
* It has an initialize function to set up the initial state which pauses the contract and sets an admin 
* It has functions to pause, resume and pause until a certain timestamp
* It has functions to request withdrawals of stETH and wstETH with and without permit
* It has functions to get withdrawal requests, status and claimable ether amounts 
* It has functions to claim withdrawals to a recipient or the owner 
* It has functions to find checkpoint hints and handle oracle reports to enable/disable bunker mode
* It emits events for initializing v1, enabling/disabling bunker mode and ERC721 transfers
# Analysis results for overflow_underflow vulnerabilities 

 Here is my analysis of the code for overflow/underflow vulnerabilities:


## Description: Possible overflow in `_requestWithdrawal()`

The `_amountOfStETH` variable is a uint256, but is cast to a uint128 when passed to `_enqueue()`. This can cause an overflow if `_amountOfStETH` is greater than 2^128.

## Impact: 
If `_amountOfStETH` overflows when cast to a uint128, the actual amount of stETH deposited will be less than intended. This can result in loss of funds for the user.

## Mitigation: 
To fix this, `_amountOfStETH` should be checked to ensure it is less than 2^128 before casting and calling `_enqueue()`. This can be done with:
```solidity
require(_amountOfStETH < 2**128, "Amount too large");
uint128 amountOfStETH = uint128(_amountOfStETH);
```




## Description: Possible underflow in `_getClaimableEther()`

The `_hint` variable is a uint256, but is used to index into the `_getQueue()` mapping which uses uint128 for keys. This can cause an underflow if `_hint` is greater than 2^128.

## Impact: 
If `_hint` underflows, it will access an incorrect key in the mapping and return the wrong `WithdrawalRequest` struct. This can result in returning an incorrect claimable ether amount.

## Mitigation:
To fix this, `_hint` should be checked to ensure it is less than 2^128 before using it to access the mapping. This can be done with:
```solidity
require(_hint < 2**128, "Hint too large");
WithdrawalRequest storage request = _getQueue()[_hint]; 
```
 



## Description: Possible overflow in `getWithdrawalRequests()`

The return value `requestsIds` is a uint256[] which can hold up to 2^256 elements. However, iterating over the entire mapping to fill this array could cause a gas limit overflow before completing.

## Impact: 
If iterating the mapping causes a gas limit overflow, the transaction will revert and the caller will not receive the full list of withdrawal requests.

## Mitigation:
To fix this, a max number of requests to return can be specified as an argument. The function can then limit the number of requests returned to this max, avoiding a potential gas limit overflow. This can be done with:
```solidity
function getWithdrawalRequests(address _owner, uint256 _maxRequests) external view returns (uint256[] memory requestsIds) {
    // Limit number of requests returned to _maxRequests
    uint256 numRequests = 0;
    for (uint256 i = 0; i < getLastRequestId() && numRequests < _maxRequests; i++) {
        if (ownerOf(i) == _owner) {
            requestsIds[numRequests++] = i;
        }
    }
}
``` 


# Analysis results for reentrancy vulnerabilities 

 Here is my audit report for the code:


## Description: Reentrancy vulnerability in claimWithdrawals()

The claimWithdrawals() function calls an external contract (STETH) to transfer funds. This opens up the possibility of a reentrancy attack where the external contract calls back into claimWithdrawals() before the first call completes.

## Impact: 

An attacker can drain funds from the contract by calling claimWithdrawals() and having the STETH contract call back into claimWithdrawals() recursively. For example:

```solidity
contract MaliciousSTETH {
  function transferFrom(address, address, uint) external {
    WithdrawalQueue(msg.sender).claimWithdrawals([1], [1]);  // Recursive call
  }
}
```

When claimWithdrawals() is first called, it will call MaliciousSTETH to transfer funds. MaliciousSTETH then calls back into claimWithdrawals(), draining more funds. This continues recursively until the contract is drained of funds.


## Mitigation:

To fix this, we can add a mutex to prevent reentrancy. For example:

```solidity
bool internal _notEntered;

function claimWithdrawals(/* ... */) internal {
  require(_notEntered);  // Check if mutex is locked
  _notEntered = false;  // Lock mutex
  
  // Function logic...
  
  _notEntered = true;  // Unlock mutex
}
```

This will prevent reentrant calls into the function, fixing the vulnerability.


# Analysis results for gas_limit_exceeded vulnerabilities 

 Here is my audit report:


## Description: The findCheckpointHints function has an unbounded gas cost due to the loop.

The findCheckpointHints function uses an unbounded loop to search for checkpoint hints. This could cause the function to consume too much gas and revert.

## Impact:

An attacker could call findCheckpointHints with a large range of indices and a large array of request IDs, causing the function to consume too much gas and revert. This would allow the attacker to manipulate the contract state without paying the full gas cost.

## Mitigation:

The findCheckpointHints function should have a max number of iterations to prevent too much gas from being consumed. This can be done by adding a check like:
```solidity
uint256 maxIterations = 100; 
for (uint256 i = 0; i < _requestIds.length && i < maxIterations; ++i) {
    // ...
}
```
This will limit the number of iterations to 100, preventing too much gas from being consumed.




## Description: The getWithdrawalRequests function has an unbounded gas cost due to copying storage to memory.  

The getWithdrawalRequests function copies the entire request mapping to memory, which can consume a large amount of gas if the mapping is very large.

## Impact:

An attacker could call getWithdrawalRequests when the request mapping is very large, causing the function to consume too much gas and revert. This would allow the attacker to manipulate the contract state without paying the full gas cost.

## Mitigation: 

The getWithdrawalRequests function should have a max number of requests to copy to memory to prevent too much gas from being consumed. This can be done by adding a check like:
```solidity
uint256 maxRequestsToCopy = 100;
uint256[] memory requests = new uint256[](maxRequestsToCopy);
uint256 count;
for (uint256 i = 0; i < _getRequestsByOwner()[_owner].length() && count < maxRequestsToCopy; ++i) {
    requests[count++] = _getRequestsByOwner()[_owner].at(i); 
}
return requests;
```
This will limit the number of requests copied to memory to 100, preventing too much gas from being consumed.


## File Analyzed: Math.sol
 ## Summary 

* Defines a Math library with utility functions 
* Defines a `max()` function to return the maximum of two uint256 numbers
* Defines a `min()` function to return the minimum of two uint256 numbers
* Defines a `pointInHalfOpenIntervalModN()` function to check if a number is in a half-open interval modulo N 
* Defines a `pointInClosedIntervalModN()` function to check if a number is in a closed interval modulo N
# Analysis results for overflow_underflow vulnerabilities 

 
## Description: Potential overflow in max() function

The max() function takes two uint256 numbers and returns the maximum value. However, if the two numbers are very large, their sum could overflow uint256 and wrap around, causing the incorrect number to be returned as the maximum.  

## Impact: 
For example, if a = 2^256 - 1 and b = 1, max(a, b) would return 1 instead of a, since (a + 1) overflows and wraps around to 0. This could have unintended consequences in the smart contract logic.


## Mitigation: 
To fix this, we can add an overflow check before summing the numbers:

```solidity
function max(uint256 a, uint256 b) internal pure returns (uint256) {
    if (a > type(uint256).max - b) return a; 
    if (b > type(uint256).max - a) return b;
    return a > b ? a : b; 
}
```

This checks if either a or b is greater than the maximum uint256 value minus the other number. If so, we immediately return the larger number to avoid an overflow. Otherwise, we sum as normal and return the maximum.
 



## Description: Potential underflow in min() function

The min() function takes two uint256 numbers and returns the minimum value. However, if the two numbers are very small, their difference could underflow uint256 and wrap around, causing the incorrect number to be returned as the minimum.

## Impact:
For example, if a = 1 and b = 2^256 - 1, min(a, b) would return b instead of a, since (b - a) underflows and wraps around to a large number. This could have unintended consequences in the smart contract logic.
  

## Mitigation:
To fix this, we can add an underflow check before subtracting the numbers:

```solidity
function min(uint256 a, uint256 b) internal pure returns (uint256) {
    if (b < a) return b;
    if (a < type(uint256).min + b) return a; 
    return a < b ? a : b;
} 
```

This checks if either a is less than the minimum uint256 value plus b, or if b is less than a. If so, we immediately return the smaller number to avoid an underflow. Otherwise, we subtract as normal and return the minimum.


# Analysis results for reentrancy vulnerabilities 

 
## Description: 

There are no vulnerabilities related to reentrancy in this code. The functions are pure (no state changes) and do not call external contracts.

## Impact:  

N/A

## Mitigation:  

N/A

# Analysis results for gas_limit_exceeded vulnerabilities 

 
## Description: No vulnerabilities found

I did not identify any gas limit vulnerabilities or other issues in the provided Math library code.  

## Impact: None

There are no vulnerabilities or issues identified in the code, so there is no impact.

## Mitigation: None needed

No mitigation is needed since no vulnerabilities were found.

