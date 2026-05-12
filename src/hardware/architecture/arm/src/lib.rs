
//////////////////////////////////////////////////////////////////
//       _    ____  __  __   ____       _                       //
//      / \  |  _ \|  \/  | |  _ \ _ __(_)_   _____ _ __ ___    //
//     / _ \ | |_) | |\/| | | | | | '__| \ \ / / _ \ '__/ __|   //
//    / ___ \|  _ <| |  | | | |_| | |  | |\ V /  __/ |  \__ \   //
//   /_/   \_\_| \_\_|  |_| |____/|_|  |_| \_/ \___|_|  |___/   //
//                                                              //
//////////////////////////////////////////////////////////////////                                 

//////////////////////////////////////////////////////////////////
//                                                              //
// Author: Stefano Mercogliano <stefano.mercogliano@unina.it>   //
//         Salvatore Bramante <salvatore.bramante@imtlucca.it>  //
//                                                              //
// Description:                                                 //
//      ARM Drivers for Cortex-M33                              //
//                                                              //
//////////////////////////////////////////////////////////////////

#![crate_name = "arm"]
#![crate_type = "rlib"]
#![no_std]
// SAFETY-comment discipline for unsafe blocks. Existing offenders raise warnings
// pending file-by-file scrub; new code is expected to be clean.
#![warn(clippy::undocumented_unsafe_blocks)]

pub mod startup;
pub mod sau;
pub mod mpu;
pub mod mmio;

