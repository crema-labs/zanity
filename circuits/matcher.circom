pragma circom 2.1.5;

include "circomlib/circuits/comparators.circom";
include "./ecies/circuits/hmac.circom";

template Matcher(n) {
    signal input ideal[n];
    signal input actual[n];
    var totalWildcards = 0;
    var totalEqual = 0;

    component isWildcard[n];
    component eqs[n];
    component selectors[n];

    for (var i = 0; i < n; i++) {
        isWildcard[i] = IsEqual();
        isWildcard[i].in[0] <== ideal[i];
        isWildcard[i].in[1] <== 46; // ASCII code for '.' 

        totalWildcards += isWildcard[i].out;

        eqs[i] = IsEqual();
        eqs[i].in[0] <== actual[i];
        eqs[i].in[1] <== ideal[i];

        // Use a selector to conditionally include the equality check
        // totalEqual = equal and not wildcard
        selectors[i] = Selector();
        selectors[i].condition <== 1 - isWildcard[i].out;
        selectors[i].in[0] <== eqs[i].out; 
        selectors[i].in[1] <== 0; // Always false if dot

        totalEqual += selectors[i].out;
    }

    component isEqual = IsEqual();
    isEqual.in[0] <== n;
    isEqual.in[1] <== totalEqual + totalWildcards;

    signal output matches;
    matches <== isEqual.out;
}



