pragma solidity ^0.8.15;

import {NitroValidator} from "./NitroValidator.sol";
import {CborDecode} from "./CborDecode.sol";
import {CertManager} from "./CertManager.sol";
import {console} from "forge-std/Test.sol";


contract EspressoValidator is NitroValidator {
    using CborDecode for bytes;

    uint256 public constant MAX_AGE = 60 minutes;
    // Put PCR0 of nsm-example here first, will update to the batcher code's later
    bytes32 public constant PCR0 = keccak256("d9f6575d313bfba9a8abea45712b8b185e2c7d3d42dc8f9b00ac8d44d870878a6a4ec8e5068263d49c955700461e8455");
    
    constructor(CertManager certManager) NitroValidator(certManager) {}

    function registerSigner(bytes calldata attestationTbs, bytes calldata signature) external { // TODO: add onlyOwner
        Ptrs memory ptrs = validateAttestation(attestationTbs, signature);
        bytes32 pcr0 = attestationTbs.keccak(ptrs.pcrs[0]);

        console.logBytes32(pcr0); // 0xc980e59163ce244bb4bb6211f48c7b46f88a4f40943e84eb99bdc41e129bd293
        console.logBytes32(PCR0); // 0x990e5b86ed64218a5427409a79ed30a657536f58c6c922c87696d4aff45703b8
        require(pcr0 == PCR0, "invalid pcr0 in attestation");
        require(ptrs.timestamp + MAX_AGE > block.timestamp, "attestation too old");

        // bytes memory publicKey = attestationTbs.slice(ptrs.publicKey);
        // do something with the public key, user data, etc
    }
}