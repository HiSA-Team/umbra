
//////////////////////////////////////////////////////////////////////
//    ____ _____ __  __ _________  _     ____                       //
//   / ___|_   _|  \/  |___ /___ \| |   | ___|_  ____  ____  __     //
//   \___ \ | | | |\/| | |_ \ __) | |   |___ \ \/ /\ \/ /\ \/ /     //
//    ___) || | | |  | |___) / __/| |___ ___) >  <  >  <  >  <      //
//   |____/ |_| |_|  |_|____/_____|_____|____/_/\_\/_/\_\/_/\_\     //
//   |  _ \ _ __(_)_   _____ _ __ ___                               //
//   | | | | '__| \ \ / / _ \ '__/ __|                              //
//   | |_| | |  | |\ V /  __/ |  \__ \                              //
//   |____/|_|  |_| \_/ \___|_|  |___/                              //
//                                                                  //
//////////////////////////////////////////////////////////////////////                    

//////////////////////////////////////////////////////////////////
//                                                              //
// Author: Stefano Mercogliano <stefano.mercogliano@unina.it>   //
//                                                              //
// Description (TBD)
//                                                              //
//////////////////////////////////////////////////////////////////

#![crate_name = "drivers"]
#![crate_type = "rlib"]
#![no_std]
// SAFETY-comment discipline for unsafe blocks. Existing offenders raise warnings
// pending file-by-file scrub; new code is expected to be clean.
#![warn(clippy::undocumented_unsafe_blocks)]

pub mod cycles;
pub mod gtzc;
pub mod uart;
pub mod rcc;
pub mod gpio;
pub mod pwr;
pub mod dma;
pub mod hash;
pub mod aes;
pub mod ofd;

#[cfg(feature = "stm32l562")]
pub mod ospi;
