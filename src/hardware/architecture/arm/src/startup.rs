//////////////////////////////////////////////////////////////////////
//                                                                  //
// Author: Stefano Mercogliano <stefano.mercogliano@unina.it>       //
//         Salvatore Bramante <salvatore.bramante@imtlucca.it>      //
//                                                                  //
// Description:                                                     //
//      ARM startup symbols. The actual assembly code lives in      //
//      asm/startup.s (compiled via build.rs + cc crate).           //
//                                                                  //
//////////////////////////////////////////////////////////////////////

#[cfg(all(target_arch = "arm", target_os = "none"))]
extern "C" {
    pub fn _umb_start();
}
