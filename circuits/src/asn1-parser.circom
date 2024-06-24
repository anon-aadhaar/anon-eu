pragma circom 2.1.9;

/// @title SelectSubArray
/// @notice Select sub array from an array given a `startIndex` and `length`
/// @notice This is same as `VarShiftLeft` but with elements after `length` set to zero
/// @notice This is not used in core ZK-Email circuits at the moment
/// @param maxArrayLen: the maximum number of bytes in the input array
/// @param maxSubArrayLen: the maximum number of integers in the output array
/// @input in: the input array
/// @input startIndex: the start index of the sub array; assumes a valid index
/// @input length: the length of the sub array; assumes to fit in `ceil(log2(maxArrayLen))` bits
/// @output out: array of `maxSubArrayLen` size, items starting from `startIndex`, and items after `length` set to zero
template SelectSubArray(maxArrayLen, maxSubArrayLen) {
    assert(maxSubArrayLen < maxArrayLen);

    signal input in[maxArrayLen];
    signal input startIndex;
    signal input length;

    signal output out[maxSubArrayLen];

    component shifter = VarShiftLeft(maxArrayLen, maxSubArrayLen);
    shifter.in <== in;
    shifter.shift <== startIndex;

    // Set value after length to zero
    component gts[maxSubArrayLen];
    for (var i = 0; i < maxSubArrayLen; i++) {
        gts[i] = GreaterThan(log2Ceil(maxSubArrayLen));
        gts[i].in[0] <== length;
        gts[i].in[1] <== i;

        out[i] <== gts[i].out * shifter.out[i];
    }
}
