// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
contract ThreatRegistry {
    struct Report { address reporter; uint256 timestamp; string category; }
    mapping(bytes32 => Report) public reports;
    event ReportRegistered(bytes32 indexed hash, address reporter, string category);
    function registerReport(bytes32 h, string calldata category) external {
        require(reports[h].timestamp == 0, "already registered");
        reports[h] = Report(msg.sender, block.timestamp, category);
        emit ReportRegistered(h, msg.sender, category);
    }
}
