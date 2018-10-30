//
//  main.cpp
//  libsnark-example
//
//  Created by su on 2018/10/27.
//  Copyright © 2018 su. All rights reserved.
//

#define CURVE_MNT6

#include <istream>
#include <libsnark/common/default_types/r1cs_ppzksnark_pp.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>
#include <libsnark/gadgetlib1/pb_variable.hpp>
#include <libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/merkle_tree/merkle_tree_check_read_gadget.hpp>

using namespace libsnark;

typedef libff::Fr<default_r1cs_ppzksnark_pp> FieldT;

void test_simple() {
    
    protoboard<FieldT> pb;
    
    pb_variable<FieldT> x;
    x.allocate(pb, "x");
    
    pb_variable<FieldT> sym_1;
    sym_1.allocate(pb, "sym_1");
    
    pb_variable<FieldT> y;
    y.allocate(pb, "y");
    
    pb_variable<FieldT> sym_2;
    sym_2.allocate(pb, "sym_2");
    
    pb_variable<FieldT> out;
    out.allocate(pb, "out");
    
    pb.set_input_sizes(1);
    
    pb.add_r1cs_constraint(r1cs_constraint<FieldT>(x, x, sym_1), "sym_1");
    pb.add_r1cs_constraint(r1cs_constraint<FieldT>(sym_1, x, y), "y");
    pb.add_r1cs_constraint(r1cs_constraint<FieldT>(y + x, 1, sym_2), "sym_2");
    pb.add_r1cs_constraint(r1cs_constraint<FieldT>(sym_2 + 5, 1, out), "out");
    
    pb.val(x)       = 3;
    pb.val(out)     = 35;
    pb.val(sym_1)   = 9;
    pb.val(y)       = 27;
    pb.val(sym_2)   = 30;


    const auto constraint_system = pb.get_constraint_system();

    // Create keypair
    auto keypair = r1cs_ppzksnark_generator<default_r1cs_ppzksnark_pp>(constraint_system);

    // Create proof
    const auto proof = r1cs_ppzksnark_prover<default_r1cs_ppzksnark_pp>(keypair.pk, pb.primary_input(), pb.auxiliary_input());

    // Verify proof
    bool verified = r1cs_ppzksnark_verifier_strong_IC<default_r1cs_ppzksnark_pp>(keypair.vk, pb.primary_input(), proof);

    std::cout << "Number of R1cs constraints: " << constraint_system.num_constraints()  << std::endl;
    std::cout << "Verification status: "        << verified                             << std::endl;

}

void test_one_input() {

    protoboard<FieldT> pb;

    block_variable<FieldT>  input(pb, SHA256_block_size, "input");
    digest_variable<FieldT> output(pb, SHA256_digest_size, "output");
    sha256_two_to_one_hash_gadget<FieldT> sha256_gadget(pb, SHA256_block_size, input, output, "hash_gadget");

    sha256_gadget.generate_r1cs_constraints();
    
    const libff::bit_vector hash_bv = libff::int_list_to_bits({0xc082e440, 0x671cd799, 0x8baf04c0, 0x22c07e03, 0x4b125ee7, 0xd28e0a59, 0x49e4b924, 0x5f5cf897}, 32);
    output.generate_r1cs_witness(hash_bv);

    //string 'hello world' 512 bytes.
    const libff::bit_vector input_bv = libff::int_list_to_bits({0x6c6c6568, 0x6f77206f, 0x00646c72, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}, 32);
    input.generate_r1cs_witness(input_bv);

    sha256_gadget.generate_r1cs_witness();

    const auto constraint_system = pb.get_constraint_system();

    // Create keypair
    auto keypair = r1cs_ppzksnark_generator<default_r1cs_ppzksnark_pp>(constraint_system);

    // Create proof
    const auto proof = r1cs_ppzksnark_prover<default_r1cs_ppzksnark_pp>(keypair.pk, pb.primary_input(), pb.auxiliary_input());

    // Verify proof
    bool verified = r1cs_ppzksnark_verifier_strong_IC<default_r1cs_ppzksnark_pp>(keypair.vk, pb.primary_input(), proof);

    std::cout << "Number of R1cs constraints: " << constraint_system.num_constraints()  << std::endl;
    std::cout << "Verification status: "        << verified                             << std::endl;
}

void test_two_input() {

    protoboard<FieldT> pb;

    digest_variable<FieldT> left(pb, SHA256_digest_size, "left");
    digest_variable<FieldT> right(pb, SHA256_digest_size, "right");
    digest_variable<FieldT> output(pb, SHA256_digest_size, "output");

    sha256_two_to_one_hash_gadget<FieldT> f(pb, left, right, output, "f");
    f.generate_r1cs_constraints();

    std::cout << "Number of constraints for sha256_two_to_one_hash_gadget:" <<  pb.num_constraints() << std::endl;

    const libff::bit_vector left_bv = libff::int_list_to_bits({0x426bc2d8, 0x4dc86782, 0x81e8957a, 0x409ec148, 0xe6cffbe8, 0xafe6ba4f, 0x9c6f1978, 0xdd7af7e9}, 32);
    const libff::bit_vector right_bv = libff::int_list_to_bits({0x038cce42, 0xabd366b8, 0x3ede7e00, 0x9130de53, 0x72cdf73d, 0xee825114, 0x8cb48d1b, 0x9af68ad0}, 32);
    const libff::bit_vector hash_bv = libff::int_list_to_bits({0xeffd0b7f, 0x1ccba116, 0x2ee816f7, 0x31c62b48, 0x59305141, 0x990e5c0a, 0xce40d33d, 0x0b1167d1}, 32);

    left.generate_r1cs_witness(left_bv);
    right.generate_r1cs_witness(right_bv);

    f.generate_r1cs_witness();
    output.generate_r1cs_witness(hash_bv);

    const auto constraint_system = pb.get_constraint_system();

    // Create keypair
    auto keypair = r1cs_ppzksnark_generator<default_r1cs_ppzksnark_pp>(constraint_system);

    // Create proof
    const auto proof = r1cs_ppzksnark_prover<default_r1cs_ppzksnark_pp>(keypair.pk, pb.primary_input(), pb.auxiliary_input());

    // Verify proof
    bool verified = r1cs_ppzksnark_verifier_strong_IC<default_r1cs_ppzksnark_pp>(keypair.vk, pb.primary_input(), proof);

    std::cout << "Number of R1cs constraints: " << constraint_system.num_constraints()  << std::endl;
    std::cout << "Verification status: "        << verified                             << std::endl;
}

int main () {
    std::cout << "begin snark test." << std::endl;

    default_r1cs_ppzksnark_pp::init_public_params();

    test_simple();
    test_one_input();
    test_two_input();

    std::cout << "end   snark test." << std::endl;
    return 0;
}
