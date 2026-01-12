// Author: Giovanni Spera  <giovanni.spera2011@libero.it>
//
// STM32L5xxxx DMA and DMAMUX Driver
// This driver implements an high level Diret Memory Access (DMA) and Diret Memory Access Multiplexer (DMAMUX) peripheral present on STM32L5xxxx.
// Both DMA1 and DMA2 (on STM32L5xxxx) can be managed by this driver, or even a custom subset of channels.
// Channels can be reserved for use outside of this driver.
// There is implemented a customizable sized queue(>= #channels) for requests.

// Crates
use peripheral_regs::*;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;

const DMA1_BASE_ADDR: u32 = 0x50020000; // Secure
const DMA2_BASE_ADDR: u32 = 0x50020400; // Secure
type DmaRegisters = u32;
type DmaChannelBitmap = u32; // A bit for channel

// A nonce is used to uniquely identify a Request.
// The ReuqestNonce is created by Dma.enqueue and is used for successive refences.
type RequestNonce = u32;

// It could be possible to allocate those at runtime
const MAX_NUMBER_OF_REQUESTS: usize = 10usize;
const NUM_OF_DMA_PERIPHERALS: DmaChannelBitmap = 2;
const NUM_OF_CHANNEL_IN_DMA: usize = 16usize;

//   _____            _     _                
//  |  __ \          (_)   | |               
//  | |__) |___  __ _ _ ___| |_ ___ _ __ ___ 
//  |  _  // _ \/ _` | / __| __/ _ \ '__/ __|
//  | | \ \  __/ (_| | \__ \ ||  __/ |  \__ \
//  |_|  \_\___|\__, |_|___/\__\___|_|  |___/
//               __/ |                       
//              |___/                      
//
//
// Contrary to the Reference Manual channels go to 0 to 7, not 1 to 8
const DMA_ISR_BASE_OFFSET      : DmaRegisters = 0x00;
const DMA_IFCR_BASE_OFFSET     : DmaRegisters = 0x04;
fn DMA_CCRx_BASE_OFFSET(x: u32)   -> DmaRegisters {0x08 + 0x14 * x }
fn DMA_CNDTRx_BASE_OFFSET(x: u32) -> DmaRegisters {0x0C + 0x14 * x }
fn DMA_CPARx_BASE_OFFSET(x: u32)  -> DmaRegisters {0x10 + 0x14 * x }
fn DMA_CM0ARx_BASE_OFFSET(x: u32) -> DmaRegisters {0x14 + 0x14 * x }
fn DMA_CM1ARx_BASE_OFFSET(x: u32) -> DmaRegisters {0x18 + 0x14 * x }

// Manages the state of a Request inside the queue.
// While the Empty state is associated to the Queue slot more than the Request,
// the state is stored by the Request itself.
#[derive(Default, Copy, Clone, PartialEq)]
enum RequestSlotState {
#[default]  Empty,
            Ready,
            Running,
            Done,
}

#[derive(Default, Copy, Clone, PartialOrd, PartialEq)]
pub enum TransferPriority {
#[default]  Low      = 0,
            Medium   = 1,
            High     = 2,
            VeryHigh = 3,
}

#[derive(Default, Copy, Clone)]
pub enum TransferSize {
#[default]  Byte     = 0, // 8 bit
            HalfWord = 1, // 16 bit
            Word     = 2, // 32 bit
            // Reserved is not a valid value
}

#[derive(Default, Copy, Clone)]
pub enum TransferSecurity {
#[default] NonSecure = 0,
           Secure    = 1,
}

// A DMA request made by the client.
// It is used to manage and query a transfer
// Contains the information needed to configure the DMA Channel, except for PRIV, SECM and EN.
// As the channel is managed by the driver the PRIV and SECM, used to configure access to the CCR register
// are not needed and must be fixed to 1.
#[derive(Default, Copy, Clone)]
pub struct Request {
    // Private fields
    nonce: RequestNonce,
    slotState: RequestSlotState,
    channel: Option<(u32, u32)>, // An optional tuple (dma instance, channel), where the transfer is ongoin

    // Configuration
    pub count: u32, // Number of transfer, up to 2^18 -1
    pub cpar : u32, // Peripheral Address
    pub cm0ar: u32, // Memory 0 Address
    pub cm1ar: u32, // Memory 1 Address

    pub dsec: TransferSecurity, // Destination security
    pub ssec: TransferSecurity, // Source security
    pub ct:   bool, // Current target, used for Double-buffer mode
    pub dbm:  bool, // Double-buffer mode
    pub mem2mem: bool, // Memory To Memory
    pub pl:   TransferPriority,
    pub msize: TransferSize,
    pub psize: TransferSize,
    pub minc: bool, // Memory increment
    pub pinc: bool, // Peripheral increment
    pub circ: bool, // Circular mode
    pub dir:  bool, // Direction, 0 read from peripheral, 1 read from memory
    pub teie: bool, // Transfer Error    Interrupt Enable
    pub htie: bool, // Half Transfer     Interrupt Enable
    pub tcie: bool, // Transfer Complete Interrupt Enable

    // TODO
    // Configure for DMAMUX
}

// The Dma manager struct, it contains and manages all the informations of the driver
pub struct Dma {
    regs: [&'static mut DmaRegisters; NUM_OF_DMA_PERIPHERALS as usize],
    reserved_chs: [DmaChannelBitmap; NUM_OF_DMA_PERIPHERALS as usize], // A bit is set if the corrisponding channel is reserved and cannot be used.
    current_nonce: RequestNonce,
    requests: [Request; MAX_NUMBER_OF_REQUESTS],
}

static mut already_init: bool = false;

impl Dma {
    const fn _new() -> Self {
        let regs = unsafe {[
            &mut *(DMA1_BASE_ADDR as *mut DmaRegisters),
            &mut *(DMA2_BASE_ADDR as *mut DmaRegisters),
        ]};

        Self {
            regs,
            requests: [const { Request::void_request() }; MAX_NUMBER_OF_REQUESTS],
            current_nonce: 1,
            reserved_chs: [0; NUM_OF_DMA_PERIPHERALS as usize],
        }
    }

    pub fn new() -> Option<Self> {
        unsafe {
            if already_init && false{
                return None
            }

            already_init = true;
        }
        
        Some(Self::_new())
    }

    // Handle queue checks for free channels in the DMA peripherals and for
    // free Requests, if any then the request will be assigned.
    // May be called when a DMA request finishes, by the handler, or when the queue/dma channel configuration is changed.
    fn handle_queue(&mut self) {
        for dma_instance in 0..NUM_OF_DMA_PERIPHERALS {
            for dma_ch in 0..NUM_OF_CHANNEL_IN_DMA {
                if !self.is_ch_free(dma_instance as u32, dma_ch as u32) {
                    continue
                }

                // Check for available request
                // In order of priority
                let maybeReq = self.pop_request();

                if let Some(requestNonce) = maybeReq {
                    // Assign
                    self.move_request_to_ch(requestNonce, dma_instance as u32, dma_ch as u32);
                } else {
                    // No request is ready
                    return;
                }
            }
        }
    }
    
    // Enqueue appends (a copy) the Request to the internal queue of the driver.
    // The request will be executed some time in the future.
    // A weak reference is returned, a strong reference can be taken to check the status of the request.
    // The strong reference cannot be taken if the driver has dropped the request or if it has completed.
    pub fn enqueue(&mut self, request: &Request) -> Option<RequestNonce> {
        // Search for the first empty slot in the array
        for i in 0..MAX_NUMBER_OF_REQUESTS {
            if self.requests[i].slotState != RequestSlotState::Empty {
                continue
            }

            // Empty slot, note that the write is not atomic
            let nonce = self.new_nonce();
            self.requests[i] = *request;
            self.requests[i].slotState = RequestSlotState::Ready;
            self.requests[i].channel = None;
            self.requests[i].nonce = nonce;
            
            // Try to move to DMA
            self.handle_queue();
            return Some(nonce)
        }
        
        None
    }
    
    fn new_nonce(&mut self) -> RequestNonce {
        let current = self.current_nonce;

        self.current_nonce += 1;

        current
    }
    
    // Check if the given channel is free to be used.
    // A reserved channel is never free.
    // For a channel to be free to EN bit in the CCRx register must be 0.
    fn is_ch_free(&self, dma_id: u32, channel: u32) -> bool {
        // Reserved
        let is_reserved = (self.reserved_chs[dma_id as usize] & (1<<channel)) != 0;
        let is_enabled = (self.read_ccrx(dma_id, channel) & 1) != 0;
        
        !is_reserved && !is_enabled
    }
    
    // Pop a Request from the queue.
    fn pop_request(&self) -> Option<RequestNonce> {
        let mut best = 0;
        let mut found = false;

        for i in 0..MAX_NUMBER_OF_REQUESTS {
            if self.requests[i].slotState != RequestSlotState::Ready {
                continue;
            }
            
            if self.requests[i].pl >= self.requests[best].pl {
                best = i;
                found = true;
            }
        }

        if found {
            Some(self.requests[best].nonce)
        } else {
            None
        }
    }
    
    // Reserve, for the specified dma peripheral the specified channel.
    // This channel will not be used for new Requests and external software
    // can use freely once running transfers are done.
    pub fn reserve_ch(&mut self, dma_id: u32, channel: u32) {
        assert!(dma_id < NUM_OF_DMA_PERIPHERALS);
        let bit = match (1 as DmaChannelBitmap). checked_shl(channel as DmaChannelBitmap) {
            Some(x) => x,
            None => panic!("Invalid channel in reserve_ch")
        };

        self.reserved_chs[dma_id as usize] |= bit;
    }
    
    // Move the given Request to the specified DMA Channel. The channel is enabled and the transfer started.
    // The Request is updated accordingly.
    fn move_request_to_ch(&mut self, requestNonce: RequestNonce, dma_id: u32, channel_id: u32) {
        // TODO: Configure DMAMUX
        // Check that the given DMA Channel is not reserved
        assert!(!self.is_channel_reserved(dma_id, channel_id));
        // Check that the given DMA Channel is free
        let ccr = self.read_ccrx(dma_id, channel_id);
        assert!(ccr & 1 == 0); // The channel is not enabled

        let index = self.get_request_index(requestNonce).unwrap();
        
        self.requests[index as usize].channel =  Some((dma_id, channel_id));
        self.requests[index as usize].slotState = RequestSlotState::Running;
        let request = self.requests[index as usize];

        // Those value persist from the previous configuration,
        // TODO: Decide the value
        let priv_: u32 = 1 << 20; // ccr & (1<<20);
        let secm:  u32 = 1 << 17; // ccr & (1<<17);

        let new_ccr: u32 = priv_             |
            ((request.dsec    as u32) << 19) |
            ((request.ssec    as u32) << 18) |
            secm                             |
            ((request.ct      as u32) << 16) |
            ((request.dbm     as u32) << 15) |
            ((request.mem2mem as u32) << 14) |
            ((request.pl      as u32) << 12) |
            ((request.msize   as u32) << 10) |
            ((request.psize   as u32) <<  8) |
            ((request.minc    as u32) << 7)  |
            ((request.pinc    as u32) << 6)  |
            ((request.circ    as u32) << 5)  |
            ((request.dir     as u32) << 4)  |
            ((request.teie    as u32) << 3)  |
            ((request.htie    as u32) << 2)  |
            1; // Enable
        
        unsafe { 
            // Clear interrupts
            write_register(self.regs[dma_id as usize], DMA_IFCR_BASE_OFFSET, 0xF<<(4 * channel_id));

            write_register(self.regs[dma_id as usize], DMA_CNDTRx_BASE_OFFSET(channel_id), request.count);
            write_register(self.regs[dma_id as usize], DMA_CPARx_BASE_OFFSET(channel_id),  request.cpar);
            write_register(self.regs[dma_id as usize], DMA_CM0ARx_BASE_OFFSET(channel_id), request.cm0ar);
            write_register(self.regs[dma_id as usize], DMA_CM1ARx_BASE_OFFSET(channel_id), request.cm1ar);
            write_register(self.regs[dma_id as usize], DMA_CCRx_BASE_OFFSET(channel_id), new_ccr);
        }
    }

    fn with_request<F>(&self, requestNonce: RequestNonce, f: F) -> bool
    where F: Fn(&Request) {
        for i in 0..MAX_NUMBER_OF_REQUESTS {
            if self.requests[i].nonce == requestNonce {
                f(&self.requests[i]);
                return true
            }
        }

        false
    }

    fn with_request_mut<F>(&mut self, requestNonce: RequestNonce, mut f: F) -> bool
    where F: FnMut(&mut Request) {
        for i in 0..MAX_NUMBER_OF_REQUESTS {
            if self.requests[i].nonce == requestNonce {
                f(&mut self.requests[i]);
                return true
            }
        }

        false
    }

    fn with_request_mut_env<F>(&self, requestNonce: RequestNonce, mut f: F) -> bool
    where F: FnMut(&Request) {
        for i in 0..MAX_NUMBER_OF_REQUESTS {
            if self.requests[i].nonce == requestNonce {
                f(&self.requests[i]);
                return true
            }
        }

        false
    }
    
    fn get_request_index(&self, nonce: RequestNonce) -> Option<u32> {
        for i in 0..MAX_NUMBER_OF_REQUESTS {
            if self.requests[i].nonce == nonce {
                return Some(i as u32)
            }
        }

        None
    }
    
    fn ack(&mut self, requestNonce: RequestNonce) -> bool {
        let mut result = false;
        if self.is_request_done(requestNonce) {
            self.with_request_mut(requestNonce, |r| {
                    r.slotState = RequestSlotState::Empty;
                    result = true;
            });
        }
        
        result
    }

    fn abort(&mut self, requestNonce: RequestNonce) -> bool {
        // TODO
        // Improve
        // Stop the request if on-flight
        self.with_request_mut(requestNonce, |r| r.slotState = RequestSlotState::Empty)
    }
    
    fn is_channel_reserved(&self, dma_id: u32, channel_id: u32) -> bool {
        self.reserved_chs[dma_id as usize] & (1<<channel_id) != 0
    }
    
    fn is_request_done(&self, requestNonce: RequestNonce) -> bool {
        let mut done = false;
        self.with_request_mut_env(requestNonce, |r| {
            if r.slotState != RequestSlotState::Running {
                return;
            }
            let (dma_id, dma_ch) = r.channel.unwrap();
            let count = self.read_cndtrx(dma_id, dma_ch);

            if count == 0 {
                // Done
                done = true;
            }
        });
        
        done
    }
    
    fn read_ccrx(&self, dma_id: u32, channel_id: u32) -> u32 {
        unsafe { read_register(self.regs[dma_id as usize], DMA_CCRx_BASE_OFFSET(channel_id)) }
    }
    fn read_cndtrx(&self, dma_id: u32, channel_id: u32) -> u32 {
        unsafe { read_register(self.regs[dma_id as usize], DMA_CNDTRx_BASE_OFFSET(channel_id)) }
    }
}

impl Request {
    const VOID_NONCE: RequestNonce = 0;

    pub fn new() -> Self {
        Self {
            nonce: Request::VOID_NONCE,
            channel: None,
            ..Default:: default()
        }
    }
    
    const fn void_request() -> Self {
        Self {
            // Private fields
            nonce: Request::VOID_NONCE,
            slotState: RequestSlotState::Empty,
            channel: None,

            count: 0,
            cpar : 0,
            cm0ar: 0,
            cm1ar: 0,

            dsec: TransferSecurity::NonSecure,
            ssec: TransferSecurity::NonSecure,
            ct:   false,
            dbm:  false,
            mem2mem: false,
            pl:   TransferPriority::Low,
            msize: TransferSize::Byte,
            psize: TransferSize::Byte,
            minc: false,
            pinc: false,
            circ: false,
            dir:  false,
            teie: false,
            htie: false,
            tcie: false,
        }
    }
}

use core::ptr;
pub fn demo() {
    // WARNING: Unsafe use of memory from address 0x30031000
    // Reads the vector table at 0x0c000000 and from 0x20000000
    let mut dma = Dma::new().unwrap();
    
    // Clear test memory area
    unsafe { ptr::write_bytes(0x30031000 as *mut u32, 0x55, 4 * 4 * 5); };

    // Create and configure Request
    let mut request = Request::new();
    request.count = 4;
    request.cpar  = 0x0c000000; // Source address
    request.cm0ar = 0x30031000; // Destination address
    request.ssec = TransferSecurity::Secure;
    request.dsec = TransferSecurity::Secure;
    request.mem2mem = true;
    request.minc = true;
    request.pinc = true;
    request.msize = TransferSize::Word;
    request.psize = TransferSize::Word;

    // Secure -> Secure
    let _nonceSS = dma.enqueue(&request);
    
    // Secure -> Non Secure
    request.ssec = TransferSecurity::Secure;
    request.dsec = TransferSecurity::NonSecure;
    request.cpar  = 0x0c000000;
    request.cm0ar = 0x20031010;
    let _nonceSNS = dma.enqueue(&request);

    // Non Secure -> Secure
    request.ssec = TransferSecurity::NonSecure;
    request.dsec = TransferSecurity::Secure;
    request.cpar  = 0x20000000;
    request.cm0ar = 0x30031020;
    let _nonceNSS = dma.enqueue(&request);
    
    // Non Secure -> Non Secure
    request.ssec = TransferSecurity::NonSecure;
    request.dsec = TransferSecurity::NonSecure;
    request.cpar  = 0x20000000;
    request.cm0ar = 0x20031030;
    let _nonceNSS = dma.enqueue(&request);
}