// SPDX-License-Identifier: AGPL-3.0

pragma solidity ^0.8.8;

import {ERC165Upgradeable} from "@openzeppelin/contracts-upgradeable/utils/introspection/ERC165Upgradeable.sol";
import {SafeCastUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/math/SafeCastUpgradeable.sol";

import {IDAO, PluginUUPSUpgradeable} from "@aragon/osx/core/plugin/PluginUUPSUpgradeable.sol";

import {IMembership} from "@aragon/osx/core/plugin/membership/IMembership.sol";
import {ProposalUpgradeable} from "@aragon/osx/core/plugin/proposal/ProposalUpgradeable.sol";
import {IProposal} from "@aragon/osx/core/plugin/proposal/IProposal.sol";

import {ISemaphoreVerifier} from "./ISemaphoreVerifier.sol";
import {LibUint1024} from "./LibUint1024.sol";
import {LibPrime} from "./LibPrime.sol";

/**@title PrivacyVoting
 * @author MH
 * @notice Wrapper around SemaphoreCicada */
contract PrivacyVoting is
    IMembership,
    ERC165Upgradeable,
    PluginUUPSUpgradeable,
    ProposalUpgradeable
{
    using LibUint1024 for *;
    using LibPrime for bytes;
    using SafeCastUpgradeable for uint256;

    /**@notice The [ERC-165](https://eips.ethereum.org/EIPS/eip-165) interface ID of the contract.*/
    bytes4 internal constant ADDRESSLIST_VOTING_INTERFACE_ID =
        this.createProposal.selector ^ this.castBallot.selector ^ this.finalizeVote.selector;

    ISemaphoreVerifier public immutable semaphoreVerifier;

    struct PublicParameters {
        uint256[4] N;
        uint256 T;
        uint256[4] g;
        uint256[4] h;
        uint256[4] y;
        uint256[4] yInv;
    }

    // TODO naming, it is referred to as tally
    struct Puzzle {
        uint256[4] u;
        uint256[4] v;
    }

    struct ProofOfExponentiation {
        uint256[4] pi;
        uint256 j;
        uint256 l;
    }

    struct ProofOfValidity {
        uint256[4] a_0;
        uint256[4] b_0;
        uint256[4] t_0;
        uint256 c_0;
        uint256[4] a_1;
        uint256[4] b_1;
        uint256[4] t_1;
        uint256 c_1;
    }

    // TODO Refactor
    struct VotingSettings {
        uint64 minDuration;
    }

    struct SemaphoreData {
        uint256 merkleRoot;
        uint256 merkleTreeDepth;
        mapping(uint256 => bool) nullifiers;
    }

    /**@notice A container for proposal-related information.
     * @param executed Whether the proposal is executed or not.
     * @param parameters The proposal parameters at the time of the proposal creation.
     * @param tally The vote tally of the proposal.
     * @param voters The votes casted by the voters.
     * @param actions The actions to be executed when the proposal passes.
     * @param allowFailureMap A bitmap allowing the proposal to succeed, even if individual actions might revert. If the bit at index `i` is 1, the proposal succeeds even if the `i`th action reverts. A failure map value of 0 requires every action to not revert.*/
    struct Proposal {
        bool executed;
        ProposalParameters parameters; // ProposalParamters
        Puzzle tally;
        mapping(uint256 => SemaphoreData) voterData;
        IDAO.Action[] actions;
        uint256 allowFailureMap;
    }

    struct ProposalParameters {
        bytes32 parametersHash;
        Puzzle tally;
        uint64 numVotes;
        uint64 startDate;
        uint64 endDate;
        bool isFinalized;
    }

    /**@notice The struct storing the voting settings.*/
    VotingSettings private votingSettings;

    /**@notice A mapping between proposal IDs and proposal information.*/
    mapping(uint256 => Proposal) internal proposals;

    /**@notice Emitted when the voting settings are updated.
     * @param minDuration The minimum duration of the proposal vote in seconds.*/
    event VotingSettingsUpdated(uint64 minDuration);
    event PublicParametersDefined(uint256 proposalId, PublicParameters publicParameters);
    event VoteFinalized(uint256 proposalId, uint64 numYesVotes, uint64 numNoVotes);

    error InvalidProofOfExponentiation();
    error InvalidPuzzleSolution();
    error InvalidBallot();
    error InvalidstartDate();
    error VoteIsNotOngoing();
    error VoteHasNotEnded();
    error VoteAlreadyFinalized();
    error ParametersHashMismatch();
    /**@notice Thrown if the proposal execution is forbidden.
     * @param proposalId The ID of the proposal.*/
    error ProposalExecutionForbidden(uint256 proposalId);
    /**@notice Thrown if a date is out of bounds.
     * @param limit The limit value.
     * @param actual The actual value. */
    error DateOutOfBounds(uint64 limit, uint64 actual);
    /**@notice Thrown if the minimal duration value is out of bounds (less than one hour or greater than 1 year).
     * @param limit The limit value.
     * @param actual The actual value.*/
    error MinDurationOutOfBounds(uint64 limit, uint64 actual);
    error DuplicateNullifier(uint256 nullifier);
    error UnsupportedMerkleTreeDepth(uint256 depth);

    constructor(ISemaphoreVerifier _semaphoreVerifier) {
        semaphoreVerifier = _semaphoreVerifier;
        _disableInitializers();
    }

    /**@notice Initializes the component.
     * @dev This method is required to support [ERC-1822](https://eips.ethereum.org/EIPS/eip-1822).
     * @param _dao The IDAO interface of the associated DAO.*/
    function initialize(IDAO _dao, VotingSettings calldata _votingSettings) external initializer {
        __PluginUUPSUpgradeable_init(_dao);
        votingSettings = _votingSettings;
    }

    /**@inheritdoc IMembership*/
    function isMember(address) external pure returns (bool) {
        return false;
    }

    /**@notice Creates a vote using the given public parameters.
     *      CAUTION: This function does not check the validity of the public parameters! Most notably, it does not check
     *          1. that _pp.N is a valid RSA modulus,
     *          2. that h = g^(2^T),
     *          3. or that g and y have Jacobi symbol 1.
     *      These should be verified off-chain (or in the inheriting contract, if desired). TODO
     * @param _metadata The metadata of the proposal.
     * @param _actions The actions that will be executed after the proposal passes.
     * @param _allowFailureMap Allows proposal to succeed even if an action reverts. Uses bitmap representation. If the bit at index `x` is 1, the tx succeeds even if the action at `x` failed. Passing 0 will be treated as atomic execution.
     * @param _startDate The start date of the proposal vote. If 0, the current timestamp is used and the vote starts immediately.
     * @param _endDate The end date of the proposal vote. If 0, `_startDate + minDuration` is used.
     * @param _pp Public parameters for the homomorphic time-lock puzzles.
     * @return proposalId The ID of the proposal.*/
    function createProposal(
        bytes calldata _metadata,
        IDAO.Action[] calldata _actions,
        uint256 _allowFailureMap,
        uint64 _startDate,
        uint64 _endDate,
        PublicParameters memory _pp
    ) external returns (uint256 proposalId) {
        _pp.g = _pp.g.normalize(_pp.N);
        _pp.h = _pp.h.normalize(_pp.N);
        _pp.y = _pp.y.normalize(_pp.N);
        _pp.yInv = _pp.yInv.normalize(_pp.N);
        // y * y^(-1) = 1 (mod N)
        if (!_pp.y.mulMod(_pp.yInv, _pp.N).eq(1.toUint1024())) {
            revert();
        }

        (_startDate, _endDate) = _validateProposalDates(_startDate, _endDate);

        proposalId = _createProposal({
            _creator: _msgSender(),
            _metadata: _metadata,
            _startDate: _startDate,
            _endDate: _endDate,
            _actions: _actions,
            _allowFailureMap: _allowFailureMap
        });

        // Store proposal related information
        Proposal storage proposal_ = proposals[proposalId];

        proposal_.parameters.startDate = _startDate;
        proposal_.parameters.endDate = _endDate;
        proposal_.parameters.tally.u = _pp.g;
        proposal_.parameters.tally.v = _pp.h;

        // Reduce costs
        if (_allowFailureMap != 0) {
            proposal_.allowFailureMap = _allowFailureMap;
        }

        for (uint256 i; i < _actions.length; ) {
            proposal_.actions.push(_actions[i]);
            unchecked {
                ++i;
            }
        }
        emit PublicParametersDefined({proposalId: proposalId, publicParameters: _pp});
    }

    function castBallot(
        uint256 _proposalId,
        PublicParameters memory _pp,
        Puzzle memory _ballot,
        ProofOfValidity memory _PoV,
        uint256 _nullifierHash,
        uint256[8] calldata _semaphoreProof
    ) external {
        Proposal storage proposal_ = proposals[_proposalId];

        if (proposal_.voterData[_proposalId].nullifiers[_nullifierHash]) {
            revert DuplicateNullifier(_nullifierHash);
        }

        semaphoreVerifier.verifyProof(
            proposal_.voterData[_proposalId].merkleRoot,
            _nullifierHash,
            uint256(keccak256(abi.encode(_ballot))),
            _proposalId,
            _semaphoreProof,
            proposal_.voterData[_proposalId].merkleTreeDepth
        );

        proposal_.voterData[_proposalId].nullifiers[_nullifierHash] = true;

        _castBallot(_proposalId, _pp, _ballot, _PoV);
    }

    function finalizeVote(
        uint256 _proposalId,
        PublicParameters memory _pp,
        uint64 _tallyPlaintext,
        uint256[4] memory _w,
        ProofOfExponentiation memory _PoE
    ) external {
        _finalizeVote(_proposalId, _pp, _tallyPlaintext, _w, _PoE);
    }

    function execute(uint256 _proposalId) external virtual {
        if (!_canExecute(_proposalId)) {
            revert ProposalExecutionForbidden(_proposalId);
        }
        _execute(_proposalId);
    }

    function canExecute(uint256 _proposalId) external view virtual returns (bool) {
        return _canExecute(_proposalId);
    }

    /**@notice Checks if this or the parent contract supports an interface by its ID.
     * @param _interfaceId The ID of the interface.
     * @return Returns `true` if the interface is supported.*/
    function supportsInterface(
        bytes4 _interfaceId
    )
        public
        view
        virtual
        override(ERC165Upgradeable, ProposalUpgradeable, PluginUUPSUpgradeable)
        returns (bool)
    {
        return
            _interfaceId == ADDRESSLIST_VOTING_INTERFACE_ID ||
            _interfaceId == type(IProposal).interfaceId ||
            _interfaceId == type(IMembership).interfaceId ||
            super.supportsInterface(_interfaceId);
    }

    /**@notice Casts a ballot for an active vote.
     * @param _proposalId The ID of the proposal.
     * @param _pp The public parameters used for the vote.
     * @param _ballot The time-lock puzzle encoding the ballot.
     * @param _PoV The proof of ballot validity.*/
    function _castBallot(
        uint256 _proposalId,
        PublicParameters memory _pp,
        Puzzle memory _ballot,
        ProofOfValidity memory _PoV
    ) internal {
        ProposalParameters storage vote = proposals[_proposalId].parameters;
        if (block.timestamp < vote.startDate || block.timestamp > vote.endDate) {
            revert VoteIsNotOngoing();
        }
        bytes32 parametersHash = keccak256(abi.encode(_pp));
        if (parametersHash != vote.parametersHash) {
            revert ParametersHashMismatch();
        }
        _verifyBallotValidity(_pp, parametersHash, _ballot, _PoV);
        vote.numVotes++;
        _updateTally(_pp, vote.tally, _ballot);
    }

    /**@notice Finalizes a vote by supplying supplying the decoded tally
     *      `tallyPlaintext` and associated proof of correctness.
     * @param _proposalId The ID of the proposal.
     * @param _pp The public parameters used for the vote.
     * @param _tallyPlaintext The purported plaintext vote tally.
     * @param _w The purported value `w := Z.u^(2^T)`, where Z
     *          is the puzzle encoding the tally.
     * @param _PoE The Wesolowski proof of exponentiation (i.e. the
     *        proof that `w = Z.u^(2^T)`)*/
    function _finalizeVote(
        uint256 _proposalId,
        PublicParameters memory _pp,
        uint64 _tallyPlaintext,
        uint256[4] memory _w,
        ProofOfExponentiation memory _PoE
    ) internal {
        ProposalParameters storage vote = proposals[_proposalId].parameters;
        if (block.timestamp < vote.endDate) {
            revert VoteHasNotEnded();
        }
        bytes32 parametersHash = keccak256(abi.encode(_pp));
        if (parametersHash != vote.parametersHash) {
            revert ParametersHashMismatch();
        }
        if (vote.isFinalized) {
            revert VoteAlreadyFinalized();
        }

        _verifySolutionCorrectness(_pp, vote.tally, _tallyPlaintext, _w, _PoE);

        vote.isFinalized = true;

        emit VoteFinalized(_proposalId, _tallyPlaintext, vote.numVotes - _tallyPlaintext);
    }

    /**@notice OR composition of two DLOG equality sigma protocols:
     *          DLOG_g(u) = DLOG_h(v) OR DLOG_g(u) = DLOG(v / y)
     *      This is equivalent to proving that there exists some
     *      value r such that:
     *          (u = g^r AND v = h^r) OR (u = v^r AND v = h^r * y)
     *      where the former case represents a "no" ballot and the
     *      latter case represents a "yes" ballot.
     * @param _pp The public parameters used for the vote.
     * @param _parametersHash The hash of `_pp`.
     * @param _Z The time-lock puzzle encoding the ballot.
     * @param _PoV The proof of ballot validity.*/
    function _verifyBallotValidity(
        PublicParameters memory _pp,
        bytes32 _parametersHash,
        Puzzle memory _Z,
        ProofOfValidity memory _PoV
    ) internal view {
        _PoV.a_0 = _PoV.a_0.normalize(_pp.N);
        _PoV.b_0 = _PoV.b_0.normalize(_pp.N);
        _PoV.a_1 = _PoV.a_1.normalize(_pp.N);
        _PoV.b_1 = _PoV.b_1.normalize(_pp.N);

        // Fiat-Shamir
        uint256 c = uint256(
            keccak256(abi.encode(_PoV.a_0, _PoV.b_0, _PoV.a_1, _PoV.b_1, _parametersHash))
        );

        // c_0 + c_1 = c (mod 2^256)
        unchecked {
            if (_PoV.c_0 + _PoV.c_1 != c) {
                revert InvalidBallot();
            }
        }

        // g^t_0 = a_0 * u^c_0 (mod N)
        uint256[4] memory lhs = _pp.g.expMod(_PoV.t_0, _pp.N).normalize(_pp.N);
        uint256[4] memory rhs = _Z.u.expMod(_PoV.c_0, _pp.N).mulMod(_PoV.a_0, _pp.N).normalize(
            _pp.N
        );
        if (!lhs.eq(rhs)) {
            revert InvalidBallot();
        }

        // h^t_0 = b_0 * v^c_0 (mod N)
        lhs = _pp.h.expMod(_PoV.t_0, _pp.N).normalize(_pp.N);
        rhs = _Z.v.expMod(_PoV.c_0, _pp.N).mulMod(_PoV.b_0, _pp.N).normalize(_pp.N);
        if (!lhs.eq(rhs)) {
            revert InvalidBallot();
        }

        // g^t_1 = a_1 * u^c_1 (mod N)
        lhs = _pp.g.expMod(_PoV.t_1, _pp.N).normalize(_pp.N);
        rhs = _Z.u.expMod(_PoV.c_1, _pp.N).mulMod(_PoV.a_1, _pp.N).normalize(_pp.N);
        if (!lhs.eq(rhs)) {
            revert InvalidBallot();
        }

        // h^t_1 = b_1 * (v * y^(-1))^c_1 (mod N)
        lhs = _pp.h.expMod(_PoV.t_1, _pp.N).normalize(_pp.N);
        rhs = _Z
            .v
            .mulMod(_pp.yInv, _pp.N)
            .expMod(_PoV.c_1, _pp.N)
            .mulMod(_PoV.b_1, _pp.N)
            .normalize(_pp.N);
        if (!lhs.eq(rhs)) {
            revert InvalidBallot();
        }
    }

    /**@notice Verifies that `s` is the plaintext tally encoded in the homomorphic timelock puzzle `Z`.
     * @param _pp The public parameters used for the vote.
     * @param _Z The time-lock puzzle encoding the tally.
     * @param _s The purported plaintext tally encoded by `Z`.
     * @param _w The purported value `w := Z.u^(2^T)`.
     * @param _PoE The Wesolowski proof of exponentiation (i.e. the proof that `w = Z.u^(2^T)`)*/
    function _verifySolutionCorrectness(
        PublicParameters memory _pp,
        Puzzle memory _Z,
        uint256 _s,
        uint256[4] memory _w,
        ProofOfExponentiation memory _PoE
    ) internal view {
        bytes32 parametersHash = keccak256(abi.encode(_pp));
        _verifyExponentiation(_pp, parametersHash, _Z.u, _w, _PoE);

        // Check v = w * y^s (mod N)
        uint256[4] memory rhs = _pp.y.expMod(_s, _pp.N).mulMod(_w, _pp.N).normalize(_pp.N);
        if (!_Z.v.eq(rhs)) {
            revert InvalidPuzzleSolution();
        }
    }

    /**@notice Validates and returns the proposal vote dates.
     * @param _start The start date of the proposal vote. If 0, the current timestamp is used and the vote starts immediately.
     * @param _end The end date of the proposal vote. If 0, `_start + minDuration` is used.
     * @return startDate The validated start date of the proposal vote.
     * @return endDate The validated end date of the proposal vote.*/
    function _validateProposalDates(
        uint64 _start,
        uint64 _end
    ) internal view virtual returns (uint64 startDate, uint64 endDate) {
        uint64 currentTimestamp = block.timestamp.toUint64();

        if (_start == 0) {
            startDate = currentTimestamp;
        } else {
            startDate = _start;

            if (startDate < currentTimestamp) {
                revert DateOutOfBounds({limit: currentTimestamp, actual: startDate});
            }
        }

        uint64 earliestEndDate = startDate + votingSettings.minDuration; // Since `minDuration` is limited to 1 year, `startDate + minDuration` can only overflow if the `startDate` is after `type(uint64).max - minDuration`. In this case, the proposal creation will revert and another date can be picked.

        if (_end == 0) {
            endDate = earliestEndDate;
        } else {
            endDate = _end;

            if (endDate < earliestEndDate) {
                revert DateOutOfBounds({limit: earliestEndDate, actual: endDate});
            }
        }
    }

    /**@notice Internal function to update the plugin-wide proposal vote settings.
     * @param _votingSettings The voting settings to be validated and updated.*/
    function _updateVotingSettings(VotingSettings calldata _votingSettings) internal virtual {
        if (_votingSettings.minDuration < 60 minutes) {
            revert MinDurationOutOfBounds({limit: 60 minutes, actual: _votingSettings.minDuration});
        }

        if (_votingSettings.minDuration > 365 days) {
            revert MinDurationOutOfBounds({limit: 365 days, actual: _votingSettings.minDuration});
        }

        votingSettings = _votingSettings;

        emit VotingSettingsUpdated({minDuration: _votingSettings.minDuration});
    }

    // Verifies the Wesolowski proof of exponentiation that:
    //     u^(2^T) = w (mod N)
    // See Section 2.1 of http://crypto.stanford.edu/~dabo/papers/VDFsurvey.pdf
    function _verifyExponentiation(
        PublicParameters memory _pp,
        bytes32 _parametersHash,
        uint256[4] memory _u,
        uint256[4] memory _w,
        ProofOfExponentiation memory _PoE
    ) private view {
        _w = _w.normalize(_pp.N);
        // Fiat-Shamir random prime
        uint256 l = _PoE.l;
        abi.encode(_u, _w, _parametersHash, _PoE.j).checkHashToPrime(l);

        uint256 r = _expMod(2, _pp.T, l); // r = 2^T (mod l)
        // Check w = π^l * u^r (mod N)
        uint256[4] memory rhs = _PoE
            .pi
            .expMod(l, _pp.N)
            .mulMod(_u.expMod(r, _pp.N), _pp.N)
            .normalize(_pp.N);
        if (!_w.eq(rhs)) {
            revert InvalidProofOfExponentiation();
        }
    }

    /**@notice Homomorphically adds the ballot value to the tally.*/
    function _updateTally(
        PublicParameters memory _pp,
        Puzzle storage _tally,
        Puzzle memory _ballot
    ) private {
        _tally.u = _tally.u.mulMod(_ballot.u, _pp.N).normalize(_pp.N);
        _tally.v = _tally.v.mulMod(_ballot.v, _pp.N).normalize(_pp.N);
    }

    /**@notice Computes (base ** exponent) % modulus.*/
    function _expMod(
        uint256 _base,
        uint256 _exponent,
        uint256 _modulus
    ) private view returns (uint256 result) {
        assembly {
            // Get free memory pointer
            let p := mload(0x40)
            // Store parameters for the EXPMOD (0x05) precompile
            mstore(p, 0x20) // Length of Base
            mstore(add(p, 0x20), 0x20) // Length of Exponent
            mstore(add(p, 0x40), 0x20) // Length of Modulus
            mstore(add(p, 0x60), _base) // Base
            mstore(add(p, 0x80), _exponent) // Exponent
            mstore(add(p, 0xa0), _modulus) // Modulus
            // Call 0x05 (EXPMOD) precompile
            if iszero(staticcall(gas(), 0x05, p, 0xc0, 0, 0x20)) {
                revert(0, 0)
            }
            result := mload(0)
            // Update free memory pointer
            mstore(0x40, add(p, 0xc0))
        }
    }

    /**@notice Internal function to check if a proposal can be executed. It assumes the queried proposal exists.
     * @param _proposalId The ID of the proposal.
     * @return True if the proposal can be executed, false otherwise.
     * @dev Threshold and minimal values are compared with `>` and `>=` comparators, respectively.*/
    function _canExecute(uint256 _proposalId) internal view virtual returns (bool) {
        Proposal storage proposal_ = proposals[_proposalId];

        // Verify that the vote has not been executed already.
        if (proposal_.executed) {
            return false;
        }

        // Verfiy that the proposal is finalized
        if (!proposal_.parameters.isFinalized) {
            return false;
        }

        return true;
    }

    /**@notice Internal function to execute a vote. It assumes the queried proposal exists.
     * @param _proposalId The ID of the proposal.*/
    function _execute(uint256 _proposalId) internal virtual {
        proposals[_proposalId].executed = true;

        _executeProposal(
            dao(),
            _proposalId,
            proposals[_proposalId].actions,
            proposals[_proposalId].allowFailureMap
        );
    }

    /** @dev This empty reserved space is put in place to allow future versions to add new variables without shifting down storage in the inheritance chain.
     * https://docs.openzeppelin.com/contracts/4.x/upgradeable#storage_gaps*/
    uint256[48] private __gap;
}
