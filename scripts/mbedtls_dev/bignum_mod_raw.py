"""Framework classes for generation of bignum mod_raw test cases."""
# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from typing import Iterator, List

from . import test_case
from . import test_data_generation
from . import bignum_common
from .bignum_data import ONLY_PRIME_MODULI

class BignumModRawTarget(test_data_generation.BaseTarget):
    #pylint: disable=abstract-method, too-few-public-methods
    """Target for bignum mod_raw test case generation."""
    target_basename = 'test_suite_bignum_mod_raw.generated'

# BEGIN MERGE SLOT 1

# END MERGE SLOT 1

# BEGIN MERGE SLOT 2

class BignumModRawSub(bignum_common.ModOperationCommon,
                      BignumModRawTarget):
    """Test cases for bignum mpi_mod_raw_sub()."""
    symbol = "-"
    test_function = "mpi_mod_raw_sub"
    test_name = "mbedtls_mpi_mod_raw_sub"
    input_style = "fixed"
    arity = 2

    def arguments(self) -> List[str]:
        return [bignum_common.quote_str(n) for n in [self.arg_a,
                                                     self.arg_b,
                                                     self.arg_n]
               ] + self.result()

    def result(self) -> List[str]:
        result = (self.int_a - self.int_b) % self.int_n
        return [self.format_result(result)]

class BignumModRawMul(bignum_common.ModOperationCommon,
                      BignumModRawTarget):
    """Test cases for bignum mpi_mod_raw_mul()."""
    symbol = "*"
    test_function = "mpi_mod_raw_mul"
    test_name = "mbedtls_mpi_mod_raw_mul"
    input_style = "arch_split"
    arity = 2

    def arguments(self) -> List[str]:
        return [self.format_result(self.to_montgomery(self.int_a)),
                self.format_result(self.to_montgomery(self.int_b)),
                bignum_common.quote_str(self.arg_n)
               ] + self.result()

    def result(self) -> List[str]:
        result = (self.int_a * self.int_b) % self.int_n
        return [self.format_result(self.to_montgomery(result))]

# END MERGE SLOT 2

# BEGIN MERGE SLOT 3

class BignumModRawInvPrime(bignum_common.ModOperationCommon,
                           BignumModRawTarget):
    """Test cases for bignum mpi_mod_raw_inv_prime()."""
    moduli = ONLY_PRIME_MODULI
    symbol = "^ -1"
    test_function = "mpi_mod_raw_inv_prime"
    test_name = "mbedtls_mpi_mod_raw_inv_prime (Montgomery form only)"
    input_style = "arch_split"
    arity = 1
    suffix = True
    montgomery_form_a = True
    disallow_zero_a = True

    def result(self) -> List[str]:
        result = bignum_common.invmod_positive(self.int_a, self.int_n)
        mont_result = self.to_montgomery(result)
        return [self.format_result(mont_result)]

# END MERGE SLOT 3

# BEGIN MERGE SLOT 4

# END MERGE SLOT 4

# BEGIN MERGE SLOT 5

class BignumModRawAdd(bignum_common.ModOperationCommon,
                      BignumModRawTarget):
    """Test cases for bignum mpi_mod_raw_add()."""
    symbol = "+"
    test_function = "mpi_mod_raw_add"
    test_name = "mbedtls_mpi_mod_raw_add"
    input_style = "fixed"
    arity = 2

    def result(self) -> List[str]:
        result = (self.int_a + self.int_b) % self.int_n
        return [self.format_result(result)]

# END MERGE SLOT 5

# BEGIN MERGE SLOT 6

class BignumModRawConvertRep(bignum_common.ModOperationCommon,
                             BignumModRawTarget):
    # This is an abstract class, it's ok to have unimplemented methods.
    #pylint: disable=abstract-method
    """Test cases for representation conversion."""
    symbol = ""
    input_style = "arch_split"
    arity = 1
    rep = bignum_common.ModulusRepresentation.INVALID

    def set_representation(self, r: bignum_common.ModulusRepresentation) -> None:
        self.rep = r

    def arguments(self) -> List[str]:
        return ([bignum_common.quote_str(self.arg_n), self.rep.symbol(),
                 bignum_common.quote_str(self.arg_a)] +
                self.result())

    def description(self) -> str:
        base = super().description()
        mod_with_rep = 'mod({})'.format(self.rep.name)
        return base.replace('mod', mod_with_rep, 1)

    @classmethod
    def test_cases_for_values(cls, rep: bignum_common.ModulusRepresentation,
                              n: str, a: str) -> Iterator[test_case.TestCase]:
        """Emit test cases for the given values (if any).

        This may emit no test cases if a isn't valid for the modulus n,
        or multiple test cases if rep requires different data depending
        on the limb size.
        """
        for bil in cls.limb_sizes:
            test_object = cls(n, a, bits_in_limb=bil)
            test_object.set_representation(rep)
            # The class is set to having separate test cases for each limb
            # size, because the Montgomery representation requires it.
            # But other representations don't require it. So for other
            # representations, emit a single test case with no dependency
            # on the limb size.
            if rep is not bignum_common.ModulusRepresentation.MONTGOMERY:
                test_object.dependencies = \
                    [dep for dep in test_object.dependencies
                     if not dep.startswith('MBEDTLS_HAVE_INT')]
            if test_object.is_valid:
                yield test_object.create_test_case()
            if rep is not bignum_common.ModulusRepresentation.MONTGOMERY:
                # A single test case (emitted, or skipped due to invalidity)
                # is enough, since this test case doesn't depend on the
                # limb size.
                break

    # The parent class doesn't support non-bignum parameters. So we override
    # test generation, in order to have the representation as a parameter.
    @classmethod
    def generate_function_tests(cls) -> Iterator[test_case.TestCase]:

        for rep in bignum_common.ModulusRepresentation.supported_representations():
            for n in cls.moduli:
                for a in cls.input_values:
                    yield from cls.test_cases_for_values(rep, n, a)

class BignumModRawCanonicalToModulusRep(BignumModRawConvertRep):
    """Test cases for mpi_mod_raw_canonical_to_modulus_rep."""
    test_function = "mpi_mod_raw_canonical_to_modulus_rep"
    test_name = "Rep canon->mod"

    def result(self) -> List[str]:
        return [self.format_result(self.convert_from_canonical(self.int_a, self.rep))]

class BignumModRawModulusToCanonicalRep(BignumModRawConvertRep):
    """Test cases for mpi_mod_raw_modulus_to_canonical_rep."""
    test_function = "mpi_mod_raw_modulus_to_canonical_rep"
    test_name = "Rep mod->canon"

    @property
    def arg_a(self) -> str:
        return self.format_arg("{:x}".format(self.convert_from_canonical(self.int_a, self.rep)))

    def result(self) -> List[str]:
        return [self.format_result(self.int_a)]

# END MERGE SLOT 6

# BEGIN MERGE SLOT 7

class BignumModRawConvertToMont(bignum_common.ModOperationCommon,
                                BignumModRawTarget):
    """ Test cases for mpi_mod_raw_to_mont_rep(). """
    test_function = "mpi_mod_raw_to_mont_rep"
    test_name = "Convert into Mont: "
    symbol = "R *"
    input_style = "arch_split"
    arity = 1

    def result(self) -> List[str]:
        result = self.to_montgomery(self.int_a)
        return [self.format_result(result)]

class BignumModRawConvertFromMont(bignum_common.ModOperationCommon,
                                  BignumModRawTarget):
    """ Test cases for mpi_mod_raw_from_mont_rep(). """
    test_function = "mpi_mod_raw_from_mont_rep"
    test_name = "Convert from Mont: "
    symbol = "1/R *"
    input_style = "arch_split"
    arity = 1

    def result(self) -> List[str]:
        result = self.from_montgomery(self.int_a)
        return [self.format_result(result)]

class BignumModRawModNegate(bignum_common.ModOperationCommon,
                            BignumModRawTarget):
    """ Test cases for mpi_mod_raw_neg(). """
    test_function = "mpi_mod_raw_neg"
    test_name = "Modular negation: "
    symbol = "-"
    input_style = "arch_split"
    arity = 1

    def result(self) -> List[str]:
        result = (self.int_n - self.int_a) % self.int_n
        return [self.format_result(result)]
# END MERGE SLOT 7

# BEGIN MERGE SLOT 8

# END MERGE SLOT 8

# BEGIN MERGE SLOT 9

# END MERGE SLOT 9

# BEGIN MERGE SLOT 10

# END MERGE SLOT 10
