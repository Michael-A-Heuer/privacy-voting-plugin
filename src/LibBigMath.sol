pragma solidity ^0.8;

library LibBigMath {
    struct BigNumber2048 {
        uint256[8] words;
    }

    using LibBigMath for *;
    
    function toBigNumber2048(uint256 x)
        internal 
        pure 
        returns (BigNumber2048 memory bn) 
    {
        bn = BigNumber2048([uint256(0), 0, 0, 0, 0, 0, 0, x]);
    }

    function add(BigNumber2048 memory a, BigNumber2048 memory b) 
        internal 
        pure
        returns (BigNumber2048 memory c)
    {
        unchecked {
            c.words[7] = a.words[7] + b.words[7];
            uint256 carry = c.words[7] < a.words[7] ? 1 : 0;
            c.words[6] = a.words[6] + b.words[6] + carry;
            carry = 
                c.words[6] < a.words[6] || 
                c.words[6] < b.words[6] || 
                (a.words[6] == type(uint256).max && b.words[6] == type(uint256).max && carry == 1) ? 1 : 0;
            c.words[5] = a.words[5] + b.words[5] + carry;
            carry = 
                c.words[5] < a.words[5] || 
                c.words[5] < b.words[5] || 
                (a.words[5] == type(uint256).max && b.words[5] == type(uint256).max && carry == 1) ? 1 : 0;

            c.words[4] = a.words[4] + b.words[4] + carry;
            carry = 
                c.words[4] < a.words[4] || 
                c.words[4] < b.words[4] || 
                (a.words[4] == type(uint256).max && b.words[4] == type(uint256).max && carry == 1) ? 1 : 0;

            c.words[3] = a.words[3] + b.words[3] + carry;
            carry = 
                c.words[3] < a.words[3] || 
                c.words[3] < b.words[3] || 
                (a.words[3] == type(uint256).max && b.words[3] == type(uint256).max && carry == 1) ? 1 : 0;

            c.words[2] = a.words[2] + b.words[2] + carry;
            carry = 
                c.words[2] < a.words[2] || 
                c.words[2] < b.words[2] || 
                (a.words[2] == type(uint256).max && b.words[2] == type(uint256).max && carry == 1) ? 1 : 0;

            c.words[1] = a.words[1] + b.words[1] + carry;
            carry = 
                c.words[1] < a.words[1] || 
                c.words[1] < b.words[1] || 
                (a.words[1] == type(uint256).max && b.words[1] == type(uint256).max && carry == 1) ? 1 : 0;

            c.words[0] = a.words[0] + b.words[0] + carry;
            carry = 
                c.words[0] < a.words[0] || 
                c.words[0] < b.words[0] || 
                (a.words[0] == type(uint256).max && b.words[0] == type(uint256).max && carry == 1) ? 1 : 0;
            if (carry != 0) {
                revert("overflow");
            }
        }
    }

    function sub(BigNumber2048 memory a, BigNumber2048 memory b) 
        internal 
        pure
        returns (BigNumber2048 memory c)
    {
        unchecked {
            c.words[7] = a.words[7] - b.words[7];
            uint256 carry = a.words[7] < b.words[7] ? 1 : 0;
            c.words[6] = a.words[6] - b.words[6] - carry;
            carry = ((a.words[6] < b.words[6]) || (a.words[6] == b.words[6] && carry == 1)) ? 1 : 0;
            c.words[5] = a.words[5] - b.words[5] - carry;
            carry = ((a.words[5] < b.words[5]) || (a.words[5] == b.words[5] && carry == 1)) ? 1 : 0;
            c.words[4] = a.words[4] - b.words[4] - carry;
            carry = ((a.words[4] < b.words[4]) || (a.words[4] == b.words[4] && carry == 1)) ? 1 : 0;
            c.words[3] = a.words[3] - b.words[3] - carry;
            carry = ((a.words[3] < b.words[3]) || (a.words[3] == b.words[3] && carry == 1)) ? 1 : 0;
            c.words[2] = a.words[2] - b.words[2] - carry;
            carry = ((a.words[2] < b.words[2]) || (a.words[2] == b.words[2] && carry == 1)) ? 1 : 0;
            c.words[1] = a.words[1] - b.words[1] - carry;
            carry = ((a.words[1] < b.words[1]) || (a.words[1] == b.words[1] && carry == 1)) ? 1 : 0;
            c.words[0] = a.words[0] - b.words[0] - carry;
            carry = ((a.words[0] < b.words[0]) || (a.words[0] == b.words[0] && carry == 1)) ? 1 : 0;
            if (carry != 0) {
                revert("underflow");
            }
        }
    }

    function eq(BigNumber2048 memory a, BigNumber2048 memory b)
        internal
        pure
        returns (bool)
    {
        return
            a.words[0] == b.words[0] &&
            a.words[1] == b.words[1] &&
            a.words[2] == b.words[2] &&
            a.words[3] == b.words[3] &&
            a.words[4] == b.words[4] &&
            a.words[5] == b.words[5] &&
            a.words[6] == b.words[6] &&
            a.words[7] == b.words[7];
    }

    function gt(BigNumber2048 memory a, BigNumber2048 memory b)
        internal
        pure
        returns (bool)
    {
        return _gt(a, b, false);
    }

    function gte(BigNumber2048 memory a, BigNumber2048 memory b)
        internal
        pure
        returns (bool)
    {
        return _gt(a, b, true);
    }

    function _gt(
        BigNumber2048 memory a, 
        BigNumber2048 memory b, 
        bool trueIfEqual
    )
        private
        pure
        returns (bool)
    {
        if (a.words[0] < b.words[0]) {
            return false;
        } else if (a.words[0] > b.words[0]) {
            return true;
        }
        if (a.words[1] < b.words[1]) {
            return false;
        } else if (a.words[1] > b.words[1]) {
            return true;
        }
        if (a.words[2] < b.words[2]) {
            return false;
        } else if (a.words[2] > b.words[2]) {
            return true;
        }
        if (a.words[3] < b.words[3]) {
            return false;
        } else if (a.words[3] > b.words[3]) {
            return true;
        }
        if (a.words[4] < b.words[4]) {
            return false;
        } else if (a.words[4] > b.words[4]) {
            return true;
        }
        if (a.words[5] < b.words[5]) {
            return false;
        } else if (a.words[5] > b.words[5]) {
            return true;
        }
        if (a.words[6] < b.words[6]) {
            return false;
        } else if (a.words[6] > b.words[6]) {
            return true;
        }
        if (a.words[7] < b.words[7]) {
            return false;
        }
        return trueIfEqual || (a.words[7] > b.words[7]);
    }

    function lt(BigNumber2048 memory a, BigNumber2048 memory b)
        internal
        pure
        returns (bool)
    {
        return _lt(a, b, false);
    }

    function lte(BigNumber2048 memory a, BigNumber2048 memory b)
        internal
        pure
        returns (bool)
    {
        return _lt(a, b, true);
    }

    function _lt(
        BigNumber2048 memory a, 
        BigNumber2048 memory b, 
        bool trueIfEqual
    )
        private
        pure
        returns (bool)
    {
        if (a.words[0] > b.words[0]) {
            return false;
        } else if (a.words[0] < b.words[0]) {
            return true;
        }
        if (a.words[1] > b.words[1]) {
            return false;
        } else if (a.words[1] < b.words[1]) {
            return true;
        }
        if (a.words[2] > b.words[2]) {
            return false;
        } else if (a.words[2] < b.words[2]) {
            return true;
        }
        if (a.words[3] > b.words[3]) {
            return false;
        } else if (a.words[3] < b.words[3]) {
            return true;
        }
        if (a.words[4] > b.words[4]) {
            return false;
        } else if (a.words[4] < b.words[4]) {
            return true;
        }
        if (a.words[5] > b.words[5]) {
            return false;
        } else if (a.words[5] < b.words[5]) {
            return true;
        }
        if (a.words[6] > b.words[6]) {
            return false;
        } else if (a.words[6] < b.words[6]) {
            return true;
        }
        if (a.words[7] > b.words[7]) {
            return false;
        } 
        return trueIfEqual || a.words[7] < b.words[7];
    }

    // function mulMod(BigNumber2048 memory a, BigNumber2048 memory b, BigNumber2048 memory modulus)
    //     internal
    //     view
    //     returns (BigNumber2048 memory result)
    // {
    //     BigNumber2048 memory sumSquared = a.add(b).expMod(2, modulus);
    //     BigNumber2048 memory differenceSquared = a.sub(b).expMod(2, modulus);
    //     // Returns (a+b)^2 - (a-b)^2 = 4ab
    //     return sumSquared.subMod(differenceSquared, modulus);
    // }

    function addMod(BigNumber2048 memory a, BigNumber2048 memory b, BigNumber2048 memory modulus)
        internal
        pure
        returns (BigNumber2048 memory result)
    {
        result = a.add(b);
        if (result.gte(modulus)) {
            result = result.sub(modulus);
        }
    }

    function subMod(BigNumber2048 memory a, BigNumber2048 memory b, BigNumber2048 memory modulus)
        internal
        pure
        returns (BigNumber2048 memory result)
    {
        if (a.gt(b)) {
            return a.sub(b);
        } else {
            return modulus.sub(b.sub(a));
        }
    }

    // function expMod(BigNumber2048 memory base, uint256 e, BigNumber2048 memory modulus)
    //     internal
    //     view
    //     returns (BigNumber2048 memory result)
    // {
    //     assembly {
    //         // Get free memory pointer
    //         let p := mload(0x40)

    //         // Store parameters for the Expmod (0x05) precompile
    //         mstore(p, 256)               // Length of Base
    //         mstore(add(p, 0x20), 0x20)   // Length of Exponent
    //         mstore(add(p, 0x40), 256)    // Length of Modulus
    //         // Use Identity (0x04) precompile to memcpy the base
    //         if iszero(staticcall(gas(), 0x04, add(base, 0x20), 256, add(p, 0x60), 256)) {
    //             revert(0, 0)
    //         }
    //         mstore(add(p, add(0x60, 256)), e) // Exponent
    //         // Use Identity (0x04) precompile to memcpy the modulus
    //         if iszero(staticcall(gas(), 0x04, add(modulus, 0x20), 256, add(add(p, 0x80), 256), 256)) {
    //             revert(0, 0)
    //         }
            
    //         // Call 0x05 (EXPMOD) precompile
    //         if iszero(staticcall(gas(), 0x05, p, add(add(0x80, 256), 256), result, 256)) {
    //             revert(0, 0)
    //         }

    //         // Update free memory pointer
    //         mstore(0x40, add(add(p, 512), 0x80))
    //     }
    // }
}