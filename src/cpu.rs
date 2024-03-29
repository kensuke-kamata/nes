use crate::opcodes::opcodes;

const STACK: u16 = 0x0100;
const STACK_RESET: u8 = 0xfd;

#[derive(Clone, Debug)]
pub struct Flags(u8);

#[allow(dead_code)]
impl Flags {
    const C: u8 = 1 << 0; // Carry
    const Z: u8 = 1 << 1; // Zero
    const I: u8 = 1 << 2; // Interrupt Disable
    const D: u8 = 1 << 3; // Decimal Mode
    const B: u8 = 1 << 4; // Break
    const U: u8 = 1 << 5; // Unused
    const V: u8 = 1 << 6; // Overflow
    const N: u8 = 1 << 7; // Negative

    pub fn set(&mut self, flag: u8) {
        self.0 |= flag;
    }

    pub fn clear(&mut self, flag: u8) {
        self.0 &= !flag;
    }

    pub fn is_set(&self, flag: u8) -> bool {
        self.0 & flag != 0
    }
}

pub struct CPU {
    pub program_counter: u16,
    pub stack_pointer: u8,
    pub register_a: u8,
    pub register_x: u8,
    pub register_y: u8,
    pub status: Flags,
    memory: [u8; 0x10000],
}

#[derive(Debug)]
#[allow(non_camel_case_types)]
pub enum AddressingMode {
    Accumulator,
    Immediate,
    ZeroPage,
    ZeroPage_X,
    ZeroPage_Y,
    Absolute,
    Absolute_X,
    Absolute_Y,
    Indirect,
    Indirect_X,
    Indirect_Y,
    NoneAddressing,
}

impl CPU {
    pub fn new() -> Self {
        CPU {
            program_counter: 0,
            stack_pointer: STACK_RESET,
            register_a: 0,
            register_x: 0,
            register_y: 0,
            status: Flags(0),
            memory: [0x00; 0x10000],
        }
    }

    pub fn reset(&mut self) {
        self.register_a = 0;
        self.register_x = 0;
        self.status = Flags(0);
        self.program_counter = self.mem_read_u16(0xfffc);
    }

    fn mem_read(&self, addr: u16) -> u8 {
        self.memory[addr as usize]
    }

    fn mem_write(&mut self, addr: u16, data: u8) {
        self.memory[addr as usize] = data;
    }

    fn mem_read_u16(&self, pos: u16) -> u16 {
        let lo = self.mem_read(pos) as u16;
        let hi = self.mem_read(pos + 1) as u16;
        hi << 8 | lo
    }

    fn mem_write_u16(&mut self, pos: u16, data: u16) {
        let hi = (data >> 8) as u8;
        let lo = (data & 0xff) as u8;
        self.mem_write(pos, lo);
        self.mem_write(pos + 1, hi);
    }

    fn stack_push(&mut self, data: u8) {
        self.mem_write(STACK + self.stack_pointer as u16, data);
        self.stack_pointer = self.stack_pointer.wrapping_sub(1);
    }

    fn stack_pop(&mut self) -> u8 {
        self.stack_pointer = self.stack_pointer.wrapping_add(1);
        self.mem_read(STACK + self.stack_pointer as u16)
    }

    fn stack_push_u16(&mut self, data: u16) {
        let hi = (data >> 8) as u8;
        let lo = (data & 0xff) as u8;
        self.stack_push(hi);
        self.stack_push(lo);
    }

    fn stack_pop_u16(&mut self) -> u16 {
        let lo = self.stack_pop() as u16;
        let hi = self.stack_pop() as u16;
        hi << 8 | lo
    }

    fn flag_zero(&mut self, result: u8) {
        if result == 0 {
            self.status.set(Flags::Z);
        } else {
            self.status.clear(Flags::Z);
        }
    }

    fn flag_overflow(&mut self, result: u8) {
        if result & Flags::V != 0 {
            self.status.set(Flags::V);
        } else {
            self.status.clear(Flags::V);
        }
    }

    fn flag_negative(&mut self, result: u8) {
        if result & Flags::N != 0 {
            self.status.set(Flags::N);
        } else {
            self.status.clear(Flags::N);
        }
    }

    fn set_register_a(&mut self, data: u8) {
        self.register_a = data;
        self.flag_zero(self.register_a);
        self.flag_negative(self.register_a);
    }

    fn set_register_x(&mut self, data: u8) {
        self.register_x = data;
        self.flag_zero(self.register_x);
        self.flag_negative(self.register_x);
    }

    fn set_register_y(&mut self, data: u8) {
        self.register_y = data;
        self.flag_zero(self.register_y);
        self.flag_negative(self.register_y);
    }

    pub fn load(&mut self, program: Vec<u8>) {
        self.memory[0x8000..(0x8000 + program.len())].copy_from_slice(&program[..]);
        self.mem_write_u16(0xfffc, 0x8000);
    }

    pub fn load_and_run(&mut self, program: Vec<u8>) {
        self.load(program);
        self.reset();
        self.run();
    }

    pub fn get_operand_address(&self, mode: &AddressingMode) -> u16 {
        match mode {
            AddressingMode::Immediate => self.program_counter,
            AddressingMode::ZeroPage => self.mem_read(self.program_counter) as u16,
            AddressingMode::Absolute | AddressingMode::Indirect => {
                let addr = self.mem_read_u16(self.program_counter);
                addr
            }
            AddressingMode::ZeroPage_X => {
                let pos = self.mem_read(self.program_counter);
                let addr = pos.wrapping_add(self.register_x) as u16;
                addr
            }
            AddressingMode::ZeroPage_Y => {
                let pos = self.mem_read(self.program_counter);
                let addr = pos.wrapping_add(self.register_y) as u16;
                addr
            }
            AddressingMode::Absolute_X => {
                let base = self.mem_read_u16(self.program_counter);
                let addr = base.wrapping_add(self.register_x as u16);
                addr
            }
            AddressingMode::Absolute_Y => {
                let base = self.mem_read_u16(self.program_counter);
                let addr = base.wrapping_add(self.register_x as u16);
                addr
            }
            AddressingMode::Indirect_X => {
                let base = self.mem_read(self.program_counter);
                let ptr = base.wrapping_add(self.register_x);
                let lo = self.mem_read(ptr as u16);
                let hi = self.mem_read(ptr.wrapping_add(1) as u16);
                (hi as u16) << 8 | lo as u16
            }
            AddressingMode::Indirect_Y => {
                let base = self.mem_read(self.program_counter);
                let lo = self.mem_read(base as u16);
                let hi = self.mem_read(base.wrapping_add(1) as u16);
                let addr = (hi as u16) << 8 | lo as u16;
                let addr = addr.wrapping_add(self.register_y as u16);
                addr
            }
            AddressingMode::Accumulator | AddressingMode::NoneAddressing => {
                panic!("mode {:?} is not supported to get operand address", mode);
            }
        }
    }

    fn add(&mut self, base: u8, data: u8) -> u8 {
        let (sum, carry1) = base.overflowing_add(data);
        let (sum, carry2) = sum.overflowing_add(if self.status.is_set(Flags::C) { 1 } else { 0 });
        let carry = carry1 || carry2;
        if carry {
            self.status.set(Flags::C);
        } else {
            self.status.clear(Flags::C);
        }
        let overflow = (base ^ sum) & (data ^ sum) & 0x80 != 0;
        if overflow {
            self.status.set(Flags::V);
        } else {
            self.status.clear(Flags::V);
        }
        sum
    }

    fn adc(&mut self, mode: &AddressingMode) {
        let addr = self.get_operand_address(mode);
        let data = self.mem_read(addr);
        let sum = self.add(self.register_a, data);
        self.set_register_a(sum);
    }

    fn sbc(&mut self, mode: &AddressingMode) {
        let addr = self.get_operand_address(mode);
        let data = self.mem_read(addr);
        let data = data.wrapping_neg().wrapping_sub(1);
        let sub = self.add(self.register_a, data);
        self.set_register_a(sub);
    }

    fn and(&mut self, mode: &AddressingMode) {
        let addr = self.get_operand_address(mode);
        let data = self.mem_read(addr);
        self.set_register_a(self.register_a & data);
    }

    fn eor(&mut self, mode: &AddressingMode) {
        let addr = self.get_operand_address(mode);
        let data = self.mem_read(addr);
        self.set_register_a(self.register_a ^ data);
    }

    fn ora(&mut self, mode: &AddressingMode) {
        let addr = self.get_operand_address(mode);
        let data = self.mem_read(addr);
        self.set_register_a(self.register_a | data);
    }

    fn shift_left(&mut self, data: u8) -> u8 {
        if data & 0x80 == 0x80 {
            self.status.set(Flags::C);
        } else {
            self.status.clear(Flags::C);
        }
        let data = data << 1;
        data
    }

    fn asl(&mut self, mode: &AddressingMode) {
        match mode {
            AddressingMode::Accumulator => {
                let data = self.shift_left(self.register_a);
                self.set_register_a(data);
            }
            _ => {
                let addr = self.get_operand_address(mode);
                let data = self.mem_read(addr);
                let data = self.shift_left(data);
                self.mem_write(addr, data);
                self.flag_zero(data);
                self.flag_negative(data);
            }
        }
    }

    fn shift_right(&mut self, data: u8) -> u8 {
        if data & 0x01 == 0x01 {
            self.status.set(Flags::C);
        } else {
            self.status.clear(Flags::C);
        }
        let data = data >> 1;
        data
    }

    fn lsr(&mut self, mode: &AddressingMode) {
        match mode {
            AddressingMode::Accumulator => {
                let data = self.shift_right(self.register_a);
                self.set_register_a(data);
            }
            _ => {
                let addr = self.get_operand_address(mode);
                let data = self.mem_read(addr);
                let data = self.shift_right(data);
                self.mem_write(addr, data);
                self.flag_zero(data);
                self.flag_negative(data);
            }
        }
    }

    fn rotate_left(&mut self, data: u8) -> u8 {
        let has_carry = self.status.is_set(Flags::C);
        if data & 0x80 == 0x80 {
            self.status.set(Flags::C);
        } else {
            self.status.clear(Flags::C);
        }
        let mut data = data << 1;
        if has_carry {
            data |= 0x01;
        }
        data
    }

    fn rol(&mut self, mode: &AddressingMode) {
        match mode {
            AddressingMode::Accumulator => {
                let data = self.rotate_left(self.register_a);
                self.set_register_a(data);
            }
            _ => {
                let addr = self.get_operand_address(mode);
                let data = self.mem_read(addr);
                let data = self.rotate_left(data);
                self.mem_write(addr, data);
                self.flag_zero(data);
                self.flag_negative(data);
            }
        }
    }

    fn rotate_right(&mut self, data: u8) -> u8 {
        let has_carry = self.status.is_set(Flags::C);
        if data & 0x01 == 0x01 {
            self.status.set(Flags::C);
        } else {
            self.status.clear(Flags::C);
        }
        let mut data = data >> 1;
        if has_carry {
            data |= 0x80;
        }
        data
    }

    fn ror(&mut self, mode: &AddressingMode) {
        match mode {
            AddressingMode::Accumulator => {
                let data = self.rotate_right(self.register_a);
                self.set_register_a(data);
            }
            _ => {
                let addr = self.get_operand_address(mode);
                let data = self.mem_read(addr);
                let data = self.rotate_right(data);
                self.mem_write(addr, data);
                self.flag_zero(data);
                self.flag_negative(data);
            }
        }
    }

    fn inc(&mut self, mode: &AddressingMode) {
        let addr = self.get_operand_address(mode);
        let data = self.mem_read(addr);
        let data = data.wrapping_add(1);
        self.mem_write(addr, data);
        self.flag_zero(data);
        self.flag_negative(data);
    }

    fn inx(&mut self) {
        self.set_register_x(self.register_x.wrapping_add(1));
    }

    fn iny(&mut self) {
        self.set_register_y(self.register_y.wrapping_add(1));
    }

    fn dec(&mut self, mode: &AddressingMode) {
        let addr = self.get_operand_address(mode);
        let data = self.mem_read(addr);
        let data = data.wrapping_sub(1);
        self.mem_write(addr, data);
        self.flag_zero(data);
        self.flag_negative(data);
    }

    fn dex(&mut self) {
        self.set_register_x(self.register_x.wrapping_sub(1));
    }

    fn dey(&mut self) {
        self.set_register_y(self.register_y.wrapping_sub(1));
    }

    fn compare(&mut self, data: u8, base: u8) {
        if data <= base {
            self.status.set(Flags::C);
        } else {
            self.status.clear(Flags::C);
        }
        let sub = base.wrapping_sub(data);
        self.flag_zero(sub);
        self.flag_negative(sub);
    }

    fn cmp(&mut self, mode: &AddressingMode) {
        let addr = self.get_operand_address(mode);
        let data = self.mem_read(addr);
        self.compare(data, self.register_a);
    }

    fn cpx(&mut self, mode: &AddressingMode) {
        let addr = self.get_operand_address(mode);
        let data = self.mem_read(addr);
        self.compare(data, self.register_x);
    }

    fn cpy(&mut self, mode: &AddressingMode) {
        let addr = self.get_operand_address(mode);
        let data = self.mem_read(addr);
        self.compare(data, self.register_y);
    }

    fn branch(&mut self, condition: bool) {
        if condition {
            let offset = self.mem_read(self.program_counter) as i8;
            let jump = self
                .program_counter
                .wrapping_add(1)
                .wrapping_add(offset as u16);
            self.program_counter = jump;
        }
    }

    fn bcc(&mut self) {
        self.branch(!self.status.is_set(Flags::C));
    }

    fn bcs(&mut self) {
        self.branch(self.status.is_set(Flags::C));
    }

    fn beq(&mut self) {
        self.branch(self.status.is_set(Flags::Z));
    }

    fn bmi(&mut self) {
        self.branch(self.status.is_set(Flags::N));
    }

    fn bne(&mut self) {
        self.branch(!self.status.is_set(Flags::Z));
    }

    fn bpl(&mut self) {
        self.branch(!self.status.is_set(Flags::N));
    }

    fn bvc(&mut self) {
        self.branch(!self.status.is_set(Flags::V));
    }

    fn bvs(&mut self) {
        self.branch(self.status.is_set(Flags::V));
    }

    fn jmp(&mut self, mode: &AddressingMode) {
        let addr = self.get_operand_address(mode);
        match mode {
            AddressingMode::Absolute => {
                self.program_counter = addr;
            }
            AddressingMode::Indirect => {
                let ptr = if addr & 0x00ff == 0xff {
                    let lo = self.mem_read(addr);
                    let hi = self.mem_read(addr & 0xff00);
                    (hi as u16) << 8 | lo as u16
                } else {
                    self.mem_read_u16(addr)
                };
                self.program_counter = ptr;
            }
            _ => {}
        }
    }

    fn jsr(&mut self, mode: &AddressingMode) {
        self.stack_push_u16(self.program_counter + 2 - 1);
        let addr = self.get_operand_address(mode);
        self.program_counter = addr;
    }

    fn rti(&mut self) {
        let flag = self.stack_pop();
        self.status.set(flag);
        self.status.clear(Flags::B);
        self.status.set(Flags::U);
        self.program_counter = self.stack_pop_u16();
    }

    fn rts(&mut self) {
        self.program_counter = self.stack_pop_u16() + 1;
    }

    fn bit(&mut self, mode: &AddressingMode) {
        let addr = self.get_operand_address(mode);
        let data = self.mem_read(addr);
        let and = self.register_a & data;
        self.flag_zero(and);
        self.flag_overflow(and);
        self.flag_negative(and);
    }

    fn sec(&mut self) {
        self.status.set(Flags::C);
    }

    fn sed(&mut self) {
        self.status.set(Flags::D);
    }

    fn sei(&mut self) {
        self.status.set(Flags::I);
    }

    fn clc(&mut self) {
        self.status.clear(Flags::C);
    }

    fn cld(&mut self) {
        self.status.clear(Flags::D);
    }

    fn cli(&mut self) {
        self.status.clear(Flags::I);
    }

    fn clv(&mut self) {
        self.status.clear(Flags::V);
    }

    fn lda(&mut self, mode: &AddressingMode) {
        let addr = self.get_operand_address(mode);
        let data = self.mem_read(addr);
        self.set_register_a(data);
    }

    fn ldx(&mut self, mode: &AddressingMode) {
        let addr = self.get_operand_address(mode);
        let data = self.mem_read(addr);
        self.set_register_x(data);
    }

    fn ldy(&mut self, mode: &AddressingMode) {
        let addr = self.get_operand_address(mode);
        let data = self.mem_read(addr);
        self.set_register_y(data);
    }

    fn sta(&mut self, mode: &AddressingMode) {
        let addr = self.get_operand_address(mode);
        self.mem_write(addr, self.register_a);
    }

    fn stx(&mut self, mode: &AddressingMode) {
        let addr = self.get_operand_address(mode);
        self.mem_write(addr, self.register_x);
    }

    fn sty(&mut self, mode: &AddressingMode) {
        let addr = self.get_operand_address(mode);
        self.mem_write(addr, self.register_y);
    }

    fn tax(&mut self) {
        self.set_register_x(self.register_a);
    }

    fn tay(&mut self) {
        self.set_register_y(self.register_a);
    }

    fn tsx(&mut self) {
        self.set_register_x(self.stack_pointer);
    }

    fn txa(&mut self) {
        self.set_register_a(self.register_x);
    }

    fn txs(&mut self) {
        self.stack_pointer = self.register_x;
    }

    fn tya(&mut self) {
        self.set_register_a(self.register_y);
    }

    fn pha(&mut self) {
        self.stack_push(self.register_a);
    }

    fn php(&mut self) {
        let mut status = self.status.clone();
        status.set(Flags::B);
        status.set(Flags::U);
        self.stack_push(status.0);
    }

    fn pla(&mut self) {
        let data = self.stack_pop();
        self.set_register_a(data);
    }

    fn plp(&mut self) {
        let flag = self.stack_pop();
        self.status.set(flag);
        self.status.clear(Flags::B);
        self.status.set(Flags::U);
    }

    pub fn run(&mut self) {
        let opcodes = opcodes();
        loop {
            let code = self.mem_read(self.program_counter);
            self.program_counter += 1;

            let opcode = opcodes
                .map
                .get(&code)
                .expect(&format!("opcode {:x} not found", code));
            let pc = self.program_counter;
            println!("code: {}, pc: {:x?}", opcode.mnemonic, pc);
            match code {
                0x00 => return,
                0xea => {}
                0x69 | 0x65 | 0x75 | 0x6d | 0x7d | 0x79 | 0x61 | 0x71 => {
                    self.adc(&opcode.mode);
                }
                0xe9 | 0xe5 | 0xf5 | 0xed | 0xfd | 0xf9 | 0xe1 | 0xf1 => {
                    self.sbc(&opcode.mode);
                }
                0x29 | 0x25 | 0x35 | 0x2d | 0x3d | 0x39 | 0x21 | 0x31 => {
                    self.and(&opcode.mode);
                }
                0x49 | 0x45 | 0x55 | 0x4d | 0x5d | 0x59 | 0x41 | 0x51 => {
                    self.eor(&opcode.mode);
                }
                0x09 | 0x05 | 0x15 | 0x0d | 0x1d | 0x19 | 0x01 | 0x11 => {
                    self.ora(&opcode.mode);
                }
                0x0a | 0x06 | 0x16 | 0x0e | 0x1e => {
                    self.asl(&opcode.mode);
                }
                0x4a | 0x46 | 0x56 | 0x4e | 0x5e => {
                    self.lsr(&opcode.mode);
                }
                0x2a | 0x26 | 0x36 | 0x2e | 0x3e => {
                    self.rol(&opcode.mode);
                }
                0x6a | 0x66 | 0x76 | 0x6e | 0x7e => {
                    self.ror(&opcode.mode);
                }
                0xe6 | 0xf6 | 0xee | 0xfe => {
                    self.inc(&opcode.mode);
                }
                0xe8 => self.inx(),
                0xc8 => self.iny(),
                0xc6 | 0xd6 | 0xce | 0xde => {
                    self.dec(&opcode.mode);
                }
                0xca => self.dex(),
                0x88 => self.dey(),
                0xc9 | 0xc5 | 0xd5 | 0xcd | 0xdd | 0xd9 | 0xc1 | 0xd1 => {
                    self.cmp(&opcode.mode);
                }
                0xe0 | 0xe4 | 0xec => {
                    self.cpx(&opcode.mode);
                }
                0xc0 | 0xc4 | 0xcc => {
                    self.cpy(&opcode.mode);
                }
                0x90 => self.bcc(),
                0xb0 => self.bcs(),
                0xf0 => self.beq(),
                0x30 => self.bmi(),
                0xd0 => self.bne(),
                0x10 => self.bpl(),
                0x50 => self.bvc(),
                0x70 => self.bvs(),
                0x4c | 0x6c => self.jmp(&opcode.mode),
                0x20 => self.jsr(&opcode.mode),
                0x40 => self.rti(),
                0x60 => self.rts(),
                0x24 | 0x2c => self.bit(&opcode.mode),
                0x38 => self.sec(),
                0xf8 => self.sed(),
                0x78 => self.sei(),
                0x18 => self.clc(),
                0xd8 => self.cld(),
                0x58 => self.cli(),
                0xb8 => self.clv(),
                0xa9 | 0xa5 | 0xb5 | 0xad | 0xbd | 0xb9 | 0xa1 | 0xb1 => {
                    self.lda(&opcode.mode);
                }
                0xa2 | 0xa6 | 0xb6 | 0xae | 0xbe => {
                    self.ldx(&opcode.mode);
                }
                0xa0 | 0xa4 | 0xb4 | 0xac | 0xbc => {
                    self.ldy(&opcode.mode);
                }
                0x85 | 0x95 | 0x8d | 0x9d | 0x99 | 0x81 | 0x91 => {
                    self.sta(&opcode.mode);
                }
                0x86 | 0x96 | 0x8e => {
                    self.stx(&opcode.mode);
                }
                0x84 | 0x94 | 0x8c => {
                    self.sty(&opcode.mode);
                }
                0xaa => self.tax(),
                0xa8 => self.tay(),
                0xba => self.tsx(),
                0x8a => self.txa(),
                0x9a => self.txs(),
                0x98 => self.tya(),
                0x48 => self.pha(),
                0x08 => self.php(),
                0x68 => self.pla(),
                0x28 => self.plp(),
                _ => {}
            }
            if pc == self.program_counter {
                self.program_counter += (opcode.len - 1) as u16;
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    /* LDA */
    #[test]
    fn test_0xa9_lda_immediate_load_data() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![0xa9, 0x05, 0x00]);
        assert_eq!(cpu.register_a, 0x05);
        assert!(!cpu.status.is_set(Flags::Z));
        assert!(!cpu.status.is_set(Flags::N));
    }

    #[test]
    fn test_0xa9_lda_zero_flag() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![0xa9, 0x00, 0x00]);
        assert!(cpu.status.is_set(Flags::Z));
    }

    #[test]
    fn test_0xa9_lda_negative_flag() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![0xa9, 0x80, 0x00]);
        assert!(cpu.status.is_set(Flags::N));
    }

    /* TAX */
    #[test]
    fn test_0xaa_tax_move_a_to_x() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![0xa9, 0x05, 0xaa, 0x00]);
        assert_eq!(cpu.register_x, 0x05);
        assert!(!cpu.status.is_set(Flags::Z));
        assert!(!cpu.status.is_set(Flags::N));
    }

    #[test]
    fn test_0xaa_tax_zero_flag() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![0xa9, 0x00, 0xaa, 0x00]);
        assert!(cpu.status.is_set(Flags::Z));
    }

    #[test]
    fn test_0xaa_tax_negative_flag() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![0xa9, 0x80, 0xaa, 0x00]);
        assert!(cpu.status.is_set(Flags::N));
    }

    /* INX */
    #[test]
    fn test_0xe8_inx_increment_x() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![0xa9, 0x05, 0xaa, 0xe8, 0x00]);
        assert_eq!(cpu.register_x, 0x06);
        assert!(!cpu.status.is_set(Flags::Z));
        assert!(!cpu.status.is_set(Flags::N));
    }

    #[test]
    fn test_0xe8_inx_zero_flag() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![0xa9, 0xff, 0xaa, 0xe8, 0x00]);
        assert_eq!(cpu.register_x, 0x00);
        assert!(cpu.status.is_set(Flags::Z));
    }

    #[test]
    fn test_0xe8_inx_negative_flag() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![0xa9, 0x7f, 0xaa, 0xe8, 0x00]);
        assert_eq!(cpu.register_x, 0x80);
        assert!(cpu.status.is_set(Flags::N));
    }

    #[test]
    fn test_inx_overflow() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![0xa9, 0xff, 0xaa, 0xe8, 0xe8, 0x00]);
        assert_eq!(cpu.register_x, 0x01);
    }

    #[test]
    fn test_5_ops_working_together() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![0xa9, 0xc0, 0xaa, 0xe8, 0x00]);
        assert_eq!(cpu.register_x, 0xc1);
    }

    #[test]
    fn test_lda_from_memory() {
        let mut cpu = CPU::new();
        cpu.mem_write(0x0010, 0x55);
        cpu.load_and_run(vec![0xa5, 0x10, 0x00]);
        assert_eq!(cpu.register_a, 0x55);
    }

    /* STA */
    #[test]
    fn test_sta_0x85_zero_page() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![
            0xa9, 0x42, // LDA #$42
            0x85, 0x10, // STA $10
            0x00, // BRK
        ]);
        assert_eq!(cpu.mem_read(0x0010), 0x42);
    }

    #[test]
    fn test_sta_0x8d_absolute() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![
            0xa9, 0x42, // LDA #$42
            0x8d, 0x34, 0x12, // STA $1234
            0x00, // BRK
        ]);
        assert_eq!(cpu.mem_read(0x1234), 0x42);
    }

    /* BRK */
    #[test]
    fn test_brk_0x00() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![0x00]);
    }

    /* NOP */
    #[test]
    fn test_nop_0xea() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![0xea]);
    }

    /* ADC */
    #[test]
    fn test_adc_0x69_immediate() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![
            0xa9, 0x0f, // LDA #$0f
            0x69, 0x01, // ADC #$01
            0x00,
        ]);
        assert_eq!(cpu.register_a, 0x10);
        assert!(!cpu.status.is_set(Flags::C));
    }

    #[test]
    fn test_adc_0x69_immediate_overflow() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![
            0xa9, 0xff, // LDA #$ff
            0x69, 0x01, // ADC #$01
            0x00,
        ]);
        assert_eq!(cpu.register_a, 0x00);
        assert!(cpu.status.is_set(Flags::C));
    }

    #[test]
    fn test_adc_0x69_immediate_has_carry() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![
            0x38, // SEC
            0xa9, 0x0f, // LDA #$0f
            0x69, 0x01, // ADC #$01
            0x00,
        ]);
        assert_eq!(cpu.register_a, 0x11);
        assert!(!cpu.status.is_set(Flags::C));
    }

    #[test]
    fn test_adc_0x69_immediate_has_carry_overflow() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![
            0x38, // SEC
            0xa9, 0xff, // LDA #$0f
            0x69, 0x00, // ADC #$01
            0x00,
        ]);
        assert_eq!(cpu.register_a, 0x00);
        assert!(cpu.status.is_set(Flags::C));
    }

    #[test]
    fn test_adc_0x69_immediate_invalid_2s_complement_plus() {
        let mut cpu = CPU::new();
        // 127 + 1 -> -128
        // 0b01111111 + 0b00000001 -> 0b10000000
        cpu.load_and_run(vec![
            0xa9, 0x7f, // LDA #$7f
            0x69, 0x01, // ADC #$01
            0x00,
        ]);
        assert_eq!(cpu.register_a, 0x80);
        assert!(cpu.status.is_set(Flags::V));
    }

    #[test]
    fn test_adc_0x69_immediate_invalid_2s_complement_minus() {
        let mut cpu = CPU::new();
        // -128 + (-1) -> 127
        // 0b10000000 + 0b11111111 -> 0b01111111
        cpu.load_and_run(vec![
            0xa9, 0x80, // LDA #$80
            0x69, 0xff, // ADC #$ff
            0x00,
        ]);
        assert_eq!(cpu.register_a, 0x7f);
        assert!(cpu.status.is_set(Flags::V));
    }

    /* SBC */
    #[test]
    fn test_sbc_0xe9_immediate() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![
            0x38, // SEC
            0xa9, 0x10, // LDA #$10
            0xe9, 0x01, // SBC #$01
            0x00,
        ]);
        assert_eq!(cpu.register_a, 0x0f);
        assert!(cpu.status.is_set(Flags::C));
    }

    #[test]
    fn test_sbc_0xe9_immediate_overflow() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![
            0x38, // SEC
            0xa9, 0x00, // LDA #$00
            0xe9, 0x01, // SBC #$01
            0x00,
        ]);
        assert_eq!(cpu.register_a, 0xff);
        assert!(!cpu.status.is_set(Flags::C));
    }

    #[test]
    fn test_sbc_0xe9_immediate_no_carry() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![
            0xa9, 0x10, // LDA #$10
            0xe9, 0x01, // SBC #$01
            0x00,
        ]);
        assert_eq!(cpu.register_a, 0x0e);
        assert!(cpu.status.is_set(Flags::C));
    }

    #[test]
    fn test_sbc_0xe9_immediate_no_carry_overflow() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![
            0xa9, 0x00, // LDA #$00
            0xe9, 0x00, // SBC #$01
            0x00,
        ]);
        assert_eq!(cpu.register_a, 0xff);
        assert!(!cpu.status.is_set(Flags::C));
    }

    #[test]
    fn test_sbc_0xe9_immediate_invalid_2s_complement_plus_minus() {
        let mut cpu = CPU::new();
        // 127 - (-1) -> -128
        // 0b01111111 - 0b11111111 -> 0b10000000
        cpu.load_and_run(vec![
            0x38, // SEC
            0xa9, 0x7f, // LDA #$7f
            0xe9, 0xff, // SBC #$ff
            0x00,
        ]);
        assert_eq!(cpu.register_a, 0x80);
        assert!(cpu.status.is_set(Flags::V));
    }

    #[test]
    fn test_sbc_0xe9_immediate_invalid_2s_complement_minus_plus() {
        let mut cpu = CPU::new();
        // -128 - 1 -> 127
        // 0b10000000 - 0b00000001 -> 0b01111111
        cpu.load_and_run(vec![
            0x38, // SEC
            0xa9, 0x80, // LDA #$80
            0xe9, 0x01, // SBC #$01
            0x00,
        ]);
        assert_eq!(cpu.register_a, 0x7f);
        assert!(cpu.status.is_set(Flags::V));
    }

    /* AND */
    #[test]
    fn test_and_0x29_immediate_zero_flag() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![
            0xa9,
            0b1010_1010, // LDA #$aa
            0x29,
            0b0101_0101, // AND #$55
            0x00,
        ]);
        assert_eq!(cpu.register_a, 0b0000_0000);
        assert!(cpu.status.is_set(Flags::Z));
    }

    #[test]
    fn test_and_0x29_immediate_negative_flag() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![
            0xa9,
            0b1010_1010, // LDA #$aa
            0x29,
            0b1000_1000, // AND #$88
            0x00,
        ]);
        assert_eq!(cpu.register_a, 0b1000_1000);
        assert!(cpu.status.is_set(Flags::N));
    }

    /* EOR */
    #[test]
    fn test_eor_0x49_immediate_zero_flag() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![
            0xa9,
            0b1010_1010, // LDA #$aa
            0x49,
            0b1010_1010, // EOR #$aa
            0x00,
        ]);
        assert_eq!(cpu.register_a, 0b0000_0000);
        assert!(cpu.status.is_set(Flags::Z));
    }

    #[test]
    fn test_eor_0x49_immediate_negative_flag() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![
            0xa9,
            0b1010_1010, // LDA #$aa
            0x49,
            0b0101_0101, // EOR #$55
            0x00,
        ]);
        assert_eq!(cpu.register_a, 0b1111_1111);
        assert!(cpu.status.is_set(Flags::N));
    }

    /* ORA */
    #[test]
    fn test_ora_0x09_immediate_zero_flag() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![
            0xa9,
            0b0000_0000, // LDA #$00
            0x09,
            0b0000_0000, // ORA #$00
            0x00,
        ]);
        assert_eq!(cpu.register_a, 0b0000_0000);
        assert!(cpu.status.is_set(Flags::Z));
    }

    #[test]
    fn test_ora_0x09_immediate_negative_flag() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![
            0xa9,
            0b1010_1010, // LDA #$aa
            0x09,
            0b0010_0010, // ORA #$22
            0x00,
        ]);
        assert_eq!(cpu.register_a, 0b1010_1010);
        assert!(cpu.status.is_set(Flags::N));
    }

    /* ASL */
    #[test]
    fn test_asl_0x0a_accumulator() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![
            0xa9, 0x80, // LDA #$80
            0x0a, // ASL
            0x00,
        ]);
        assert_eq!(cpu.register_a, 0x00);
        assert!(cpu.status.is_set(Flags::C));
        assert!(cpu.status.is_set(Flags::Z));
    }

    #[test]
    fn test_asl_0x06_zero_page() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![
            0xa9, 0x40, // LDA #$40
            0x85, 0x10, // STA $10
            0x06, 0x10, // ASL $10
            0x00,
        ]);
        assert_eq!(cpu.mem_read(0x10), 0x80);
        assert!(!cpu.status.is_set(Flags::C));
        assert!(cpu.status.is_set(Flags::N));
    }

    /* LSR */
    #[test]
    fn test_lsr_0x4a_accumulator() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![
            0xa9, 0x01, // LDA #$01
            0x4a, // LSR
            0x00,
        ]);
        assert_eq!(cpu.register_a, 0x00);
        assert!(cpu.status.is_set(Flags::C));
        assert!(cpu.status.is_set(Flags::Z));
        assert!(!cpu.status.is_set(Flags::N));
    }

    #[test]
    fn test_lsr_0x46_zero_page() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![
            0xa9, 0x10, // LDA #$10
            0x85, 0x10, // STA $10
            0x46, 0x10, // LSR $10
            0x00,
        ]);
        assert_eq!(cpu.mem_read(0x10), 0x08);
        assert!(!cpu.status.is_set(Flags::C));
        assert!(!cpu.status.is_set(Flags::Z));
        assert!(!cpu.status.is_set(Flags::N));
    }

    /* ROL */
    #[test]
    fn test_rol_0x2a_accumulator() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![
            0xa9, 0x80, // LDA #$80
            0x2a, // ROL
            0x00,
        ]);
        assert_eq!(cpu.register_a, 0x00);
        assert!(cpu.status.is_set(Flags::C));
        assert!(cpu.status.is_set(Flags::Z));
        assert!(!cpu.status.is_set(Flags::N));
    }

    #[test]
    fn test_rol_0x2a_accumulator_carry() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![
            0x38, // SEC
            0xa9, 0x40, // LDA #$40
            0x2a, // ROL
            0x00,
        ]);
        assert_eq!(cpu.register_a, 0x81);
        assert!(!cpu.status.is_set(Flags::C));
        assert!(!cpu.status.is_set(Flags::Z));
        assert!(cpu.status.is_set(Flags::N));
    }

    #[test]
    fn test_rol_0x26_zero_page() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![
            0xa9, 0x80, // LDA #$80
            0x85, 0x10, // STA $10
            0x26, 0x10, // ROL $10
            0x00,
        ]);
        assert_eq!(cpu.mem_read(0x10), 0x00);
        assert!(cpu.status.is_set(Flags::C));
        assert!(cpu.status.is_set(Flags::Z));
        assert!(!cpu.status.is_set(Flags::N));
    }

    #[test]
    fn test_rol_0x26_zero_page_carry() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![
            0x38, // SEC
            0xa9, 0x40, // LDA #$40
            0x85, 0x10, // STA $10
            0x26, 0x10, // ROL $10
            0x00,
        ]);
        assert_eq!(cpu.mem_read(0x10), 0x81);
        assert!(!cpu.status.is_set(Flags::C));
        assert!(!cpu.status.is_set(Flags::Z));
        assert!(cpu.status.is_set(Flags::N));
    }

    /* ROR */
    #[test]
    fn test_ror_0x6a_accumulator() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![
            0xa9, 0x01, // LDA #$01
            0x6a, // ROR
            0x00,
        ]);
        assert_eq!(cpu.register_a, 0x00);
        assert!(cpu.status.is_set(Flags::C));
        assert!(cpu.status.is_set(Flags::Z));
        assert!(!cpu.status.is_set(Flags::N));
    }

    #[test]
    fn test_ror_0x6a_accumulator_carry() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![
            0x38, // SEC
            0xa9, 0x01, // LDA #$01
            0x6a, // ROR
            0x00,
        ]);
        assert_eq!(cpu.register_a, 0x80);
        assert!(cpu.status.is_set(Flags::C));
        assert!(!cpu.status.is_set(Flags::Z));
        assert!(cpu.status.is_set(Flags::N));
    }

    #[test]
    fn test_ror_0x66_zero_page() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![
            0xa9, 0x01, // LDA #$01
            0x85, 0x10, // STA $10
            0x66, 0x10, // ROR $10
            0x00,
        ]);
        assert_eq!(cpu.mem_read(0x10), 0x00);
        assert!(cpu.status.is_set(Flags::C));
        assert!(cpu.status.is_set(Flags::Z));
        assert!(!cpu.status.is_set(Flags::N));
    }

    #[test]
    fn test_ror_0x66_zero_page_carry() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![
            0x38, // SEC
            0xa9, 0x81, // LDA #$81
            0x85, 0x10, // STA $10
            0x66, 0x10, // ROR $10
            0x00,
        ]);
        assert_eq!(cpu.mem_read(0x10), 0xC0);
        assert!(cpu.status.is_set(Flags::C));
        assert!(!cpu.status.is_set(Flags::Z));
        assert!(cpu.status.is_set(Flags::N));
    }

    /* INC */
    #[test]
    fn test_inc_0xe6_zero_page_zero_flag() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![
            0xa9, 0xff, // LDA #$ff
            0x85, 0x10, // STA $10
            0xe6, 0x10, // INC $10
            0x00,
        ]);
        assert_eq!(cpu.mem_read(0x10), 0x00);
        assert!(cpu.status.is_set(Flags::Z));
        assert!(!cpu.status.is_set(Flags::N));
    }

    #[test]
    fn test_inc_0xe6_zero_page_negative_flag() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![
            0xa9, 0x7f, // LDA #$7f
            0x85, 0x10, // STA $10
            0xe6, 0x10, // INC $10
            0x00,
        ]);
        assert_eq!(cpu.mem_read(0x10), 0x80);
        assert!(!cpu.status.is_set(Flags::Z));
        assert!(cpu.status.is_set(Flags::N));
    }

    /* INX */
    #[test]
    fn test_inx_0xe8_zero_flag() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![
            0xa2, 0xff, // LDX #$ff
            0xe8, // INX
            0x00,
        ]);
        assert_eq!(cpu.register_x, 0x00);
        assert!(cpu.status.is_set(Flags::Z));
        assert!(!cpu.status.is_set(Flags::N));
    }

    #[test]
    fn test_inx_0xe8_negative_flag() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![
            0xa2, 0x7f, // LDX #$7f
            0xe8, // INX
            0x00,
        ]);
        assert_eq!(cpu.register_x, 0x80);
        assert!(!cpu.status.is_set(Flags::Z));
        assert!(cpu.status.is_set(Flags::N));
    }

    /* INY */
    #[test]
    fn test_iny_0xc8_zero_flag() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![
            0xa0, 0xff, // LDY #$ff
            0xc8, // INY
            0x00,
        ]);
        assert_eq!(cpu.register_y, 0x00);
        assert!(cpu.status.is_set(Flags::Z));
        assert!(!cpu.status.is_set(Flags::N));
    }

    #[test]
    fn test_iny_0xc8_negative_flag() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![
            0xa0, 0x7f, // LDY #$7f
            0xc8, // INY
            0x00,
        ]);
        assert_eq!(cpu.register_y, 0x80);
        assert!(!cpu.status.is_set(Flags::Z));
        assert!(cpu.status.is_set(Flags::N));
    }

    /* DEC */
    #[test]
    fn test_dec_0xc6_zero_page_zero_flag() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![
            0xa9, 0x01, // LDA #$01
            0x85, 0x10, // STA $10
            0xc6, 0x10, // DEC $10
            0x00,
        ]);
        assert_eq!(cpu.mem_read(0x10), 0x00);
        assert!(cpu.status.is_set(Flags::Z));
        assert!(!cpu.status.is_set(Flags::N));
    }

    #[test]
    fn test_dec_0xc6_zero_page_negative_flag() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![
            0xa9, 0x00, // LDA #$00
            0x85, 0x10, // STA $10
            0xc6, 0x10, // DEC $10
            0x00,
        ]);
        assert_eq!(cpu.mem_read(0x10), 0xff);
        assert!(!cpu.status.is_set(Flags::Z));
        assert!(cpu.status.is_set(Flags::N));
    }

    /* DEX */
    #[test]
    fn test_dex_0xca_zero_flag() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![
            0xa2, 0x01, // LDX #$01
            0xca, // DEX
            0x00,
        ]);
        assert_eq!(cpu.register_x, 0x00);
        assert!(cpu.status.is_set(Flags::Z));
        assert!(!cpu.status.is_set(Flags::N));
    }

    #[test]
    fn test_dex_0xca_negative_flag() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![
            0xa2, 0x00, // LDX #$00
            0xca, // DEX
            0x00,
        ]);
        assert_eq!(cpu.register_x, 0xff);
        assert!(!cpu.status.is_set(Flags::Z));
        assert!(cpu.status.is_set(Flags::N));
    }

    /* DEY */
    #[test]
    fn test_dey_0x88_zero_flag() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![
            0xa0, 0x01, // LDY #$01
            0x88, // DEY
            0x00,
        ]);
        assert_eq!(cpu.register_y, 0x00);
        assert!(cpu.status.is_set(Flags::Z));
        assert!(!cpu.status.is_set(Flags::N));
    }

    #[test]
    fn test_dey_0x88_negative_flag() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![
            0xa0, 0x00, // LDY #$00
            0x88, // DEY
            0x00,
        ]);
        assert_eq!(cpu.register_y, 0xff);
        assert!(!cpu.status.is_set(Flags::Z));
        assert!(cpu.status.is_set(Flags::N));
    }

    /* CMP */
    #[test]
    fn test_cmp_0xc9_immediate_carry_zero_flag() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![
            0xa9, 0x01, // LDA #$01
            0xc9, 0x01, // CMP #$01
            0x00,
        ]);
        assert!(cpu.status.is_set(Flags::C));
        assert!(cpu.status.is_set(Flags::Z));
        assert!(!cpu.status.is_set(Flags::N));
    }

    #[test]
    fn test_cmp_0xc9_immediate_negative_flag() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![
            0xa9, 0x01, // LDA #$01
            0xc9, 0x02, // CMP #$02
            0x00,
        ]);
        assert!(!cpu.status.is_set(Flags::C));
        assert!(!cpu.status.is_set(Flags::Z));
        assert!(cpu.status.is_set(Flags::N));
    }

    /* CPX */
    #[test]
    fn test_cpx_0xe0_immediate_carry_zero_flag() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![
            0xa2, 0x01, // LDX #$01
            0xe0, 0x01, // CPX #$01
            0x00,
        ]);
        assert!(cpu.status.is_set(Flags::C));
        assert!(cpu.status.is_set(Flags::Z));
        assert!(!cpu.status.is_set(Flags::N));
    }

    #[test]
    fn test_cpx_0xe0_immediate_negative_flag() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![
            0xa2, 0x01, // LDX #$01
            0xe0, 0x02, // CPX #$02
            0x00,
        ]);
        assert!(!cpu.status.is_set(Flags::C));
        assert!(!cpu.status.is_set(Flags::Z));
        assert!(cpu.status.is_set(Flags::N));
    }

    /* CPY */
    #[test]
    fn test_cpy_0xc0_immediate_carry_zero_flag() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![
            0xa0, 0x01, // LDY #$01
            0xc0, 0x01, // CPY #$01
            0x00,
        ]);
        assert!(cpu.status.is_set(Flags::C));
        assert!(cpu.status.is_set(Flags::Z));
        assert!(!cpu.status.is_set(Flags::N));
    }

    #[test]
    fn test_cpy_0xc0_immediate_negative_flag() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![
            0xa0, 0x01, // LDY #$01
            0xc0, 0x02, // CPY #$02
            0x00,
        ]);
        assert!(!cpu.status.is_set(Flags::C));
        assert!(!cpu.status.is_set(Flags::Z));
        assert!(cpu.status.is_set(Flags::N));
    }

    /* BCC */
    #[test]
    fn test_bcc_0x90() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![
            0x90, 0x02, // BCC +2
            0x00, 0x00, // BRK BRK
            0xa9, 0x01, // LDA #$01
        ]);
        assert_eq!(cpu.program_counter, 0x8000 + 0x07);
        assert_eq!(cpu.register_a, 0x01);
    }

    /* BCS */
    #[test]
    fn test_bcs_0xb0() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![
            0x38, // SEC
            0xb0, 0x02, // BCS +2
            0x00, 0x00, // BRK BRK
            0xa9, 0x01, // LDA #$01
        ]);
        assert_eq!(cpu.program_counter, 0x8000 + 0x08);
        assert_eq!(cpu.register_a, 0x01);
    }

    /* BEQ */
    #[test]
    fn test_beq_0xf0() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![
            0xa9, 0x00, // LDA #$00
            0xf0, 0x02, // BEQ +2
            0x00, 0x00, // BRK BRK
            0xa9, 0x01, // LDA #$02
        ]);
        assert_eq!(cpu.program_counter, 0x8000 + 0x09);
        assert_eq!(cpu.register_a, 0x01);
    }

    /* BMI */
    #[test]
    fn test_bmi_0x30() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![
            0xa9, 0xff, // LDA #$ff
            0x30, 0x02, // BMI +2
            0x00, 0x00, // BRK BRK
            0xa9, 0x01, // LDA #$01
        ]);
        assert_eq!(cpu.program_counter, 0x8000 + 0x09);
        assert_eq!(cpu.register_a, 0x01);
    }

    /* BNE */
    #[test]
    fn test_bne_0xd0() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![
            0xa9, 0x01, // LDA #$01
            0xd0, 0x02, // BNE +2
            0x00, 0x00, // BRK BRK
            0xa9, 0x02, // LDA #$02
        ]);
        assert_eq!(cpu.program_counter, 0x8000 + 0x09);
        assert_eq!(cpu.register_a, 0x02);
    }

    /* BPL */
    #[test]
    fn test_bpl_0x10() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![
            0xa9, 0x01, // LDA #$01
            0x10, 0x02, // BPL +2
            0x00, 0x00, // BRK BRK
            0xa9, 0x02, // LDA #$02
        ]);
        assert_eq!(cpu.program_counter, 0x8000 + 0x09);
        assert_eq!(cpu.register_a, 0x02);
    }

    /* BVC */
    #[test]
    fn test_bvc_0x50() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![
            0xa9, 0x7f, // LDA #$7f
            0x69, 0x01, // ADC #$01
            0x50, 0x02, // BVC +2
            0x00, 0x00, // BRK BRK
            0xa9, 0x02, // LDA #$02
        ]);
        assert!(cpu.status.is_set(Flags::V));
        assert_eq!(cpu.register_a, 0x80);
        assert_eq!(cpu.program_counter, 0x8000 + 0x07);
    }

    /* BVS */
    #[test]
    fn test_bvs_0x70() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![
            0xa9, 0x7f, // LDA #$7f
            0x69, 0x01, // ADC #$01
            0x70, 0x02, // BVS +2
            0x00, 0x00, // BRK BRK
            0xa9, 0x02, // LDA #$02
        ]);
        assert!(cpu.status.is_set(Flags::V));
        assert_eq!(cpu.register_a, 0x02);
        assert_eq!(cpu.program_counter, 0x8000 + 0x0b);
    }

    /* JMP */
    #[test]
    fn test_jmp_0x4c_absolute() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![
            0x4c, 0x10, 0x80, // JMP $8010
        ]);
        assert_eq!(cpu.program_counter, 0x8011);
    }

    #[test]
    fn test_jmp_0x6c_indirect() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![
            0xa9, 0x10, // LDA #$10
            0x85, 0x10, // STA $10
            0x85, 0x11, // STA $11
            0x6c, 0x10, 0x00, // JMP ($0010)
        ]);
        assert_eq!(cpu.program_counter, 0x1011);
    }

    #[test]
    fn test_jmp_0x6c_indirect_6502_bug() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![
            0xa9, 0x10, // LDA #$10
            0x8d, 0x00, 0x50, // STA $5000
            0xa9, 0x20, // LDA #$20
            0x8d, 0xff, 0x50, // STA $50ff
            0xa9, 0x30, // LDA #$30
            0x8d, 0x00, 0x51, // STA $5100
            0x6c, 0xff, 0x50, // JMP ($50ff)
        ]);
        assert_ne!(cpu.program_counter, 0x3021);
        assert_eq!(cpu.program_counter, 0x1021);
    }

    /* JSR */
    #[test]
    fn test_jsr_0x20() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![
            0x20, 0x10, 0x80, // JSR $8010
        ]);
        assert_eq!(cpu.program_counter, 0x8011);
        assert_eq!(
            cpu.mem_read_u16(STACK + cpu.stack_pointer as u16 + 1),
            0x8002
        );
    }

    /* RTS */
    #[test]
    fn test_rts_0x60() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![
            0x20, 0x06, 0x80, // JSR $8006
            0xa9, 0x01, // LDA #$01
            0x00, // BRK
            0x60, // RTS
        ]);
        assert_eq!(cpu.program_counter, 0x8006);
    }

    /* RTI */
    #[test]
    fn test_rti_0x40() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![
            0xa9, 0x10, // LDA #$11
            0x48, // PHA
            0xa9, 0x11, // LDA #$10
            0x48, // PHA
            0x38, // SEC
            0xf8, // SED
            0x78, // SEI
            0x08, // PHP
            0x18, // CLC
            0xd8, // CLD
            0x58, // CLI
            0x40, // RTI
        ]);
        assert!(cpu.status.is_set(Flags::C));
        assert!(cpu.status.is_set(Flags::D));
        assert!(cpu.status.is_set(Flags::I));
        assert_eq!(cpu.program_counter, 0x1012);
    }

    /* BIT */
    #[test]
    fn test_bit_0x24_zero_page() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![
            0xa9, 0xaa, // LDA #$aa
            0x85, 0x10, // STA $10
            0xa9, 0x55, // LDA #$55
            0x24, 0x10, // BIT $10
        ]);
        assert!(cpu.status.is_set(Flags::Z));
        assert!(!cpu.status.is_set(Flags::V));
        assert!(!cpu.status.is_set(Flags::N));
    }

    #[test]
    fn test_bit_0x2c_absolute() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![
            0xa9, 0xc0, // LDA #$c0
            0x8d, 0x00, 0x10, // STA $1000
            0xa9, 0xff, // LDA #$ff
            0x2c, 0x00, 0x10, // BIT $1000
        ]);
        assert!(!cpu.status.is_set(Flags::Z));
        assert!(cpu.status.is_set(Flags::V));
        assert!(cpu.status.is_set(Flags::N));
    }

    /* SEC */
    #[test]
    fn test_sec_0x38() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![0x38, 0x00]);
        assert!(cpu.status.is_set(Flags::C));
    }

    /* TAX */
    #[test]
    fn test_tax_0xaa() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![
            0xa9, 0x80, // LDA #$80
            0xaa, // TAX
        ]);
        assert_eq!(cpu.register_x, 0x80);
        assert!(!cpu.status.is_set(Flags::Z));
        assert!(cpu.status.is_set(Flags::N));
    }

    /* TAY */
    #[test]
    fn test_tay_0xaa() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![
            0xa9, 0x80, // LDA #$80
            0xa8, // TAY
        ]);
        assert_eq!(cpu.register_y, 0x80);
        assert!(!cpu.status.is_set(Flags::Z));
        assert!(cpu.status.is_set(Flags::N));
    }

    /* TSX */
    #[test]
    fn test_tsx_0xba() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![
            0xa9, 0x10, // LDA #$10
            0x48, // PHA
            0xba, // TSX
        ]);
        assert_eq!(cpu.register_x, cpu.stack_pointer);
        assert!(!cpu.status.is_set(Flags::Z));
        assert!(cpu.status.is_set(Flags::N));
    }

    /* TXA */
    #[test]
    fn test_txa_0x8a() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![
            0xa2, 0x80, // LDX #$80
            0x8a, // TXA
        ]);
        assert_eq!(cpu.register_a, 0x80);
        assert!(!cpu.status.is_set(Flags::Z));
        assert!(cpu.status.is_set(Flags::N));
    }

    /* TXS */
    #[test]
    fn test_txs_0x9a() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![
            0xa2, 0x80, // LDX #$80
            0x9a, // TXS
        ]);
        assert_eq!(cpu.stack_pointer, 0x80);
    }

    /* TYA */
    #[test]
    fn test_tya_0x98() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![
            0xa0, 0x80, // LDY #$80
            0x98, // TYA
        ]);
        assert_eq!(cpu.register_a, 0x80);
        assert!(!cpu.status.is_set(Flags::Z));
        assert!(cpu.status.is_set(Flags::N));
    }

    /* PHA */
    #[test]
    fn test_pha_0x48() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![
            0xa9, 0x80, // LDA #$80
            0x48, // PHA
        ]);
        assert_eq!(cpu.mem_read(STACK + cpu.stack_pointer as u16 + 1), 0x80);
        assert_eq!(cpu.stack_pointer, 0xfc);
    }

    /* PHP */
    #[test]
    fn test_php_0x08() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![
            0x08, // PHP
        ]);
        assert_eq!(cpu.mem_read(STACK + cpu.stack_pointer as u16 + 1), 0x30);
        assert_eq!(cpu.stack_pointer, 0xfc);
    }

    /* PLA */
    #[test]
    fn test_pla_0x68() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![
            0xa9, 0x80, // LDA #$80
            0x48, // PHA
            0xa9, 0x00, // LDA #$00
            0x68, // PLA
        ]);
        assert_eq!(cpu.register_a, 0x80);
        assert_eq!(cpu.stack_pointer, 0xfd);
        assert!(!cpu.status.is_set(Flags::Z));
        assert!(cpu.status.is_set(Flags::N));
    }

    /* PLP */
    #[test]
    fn test_plp_0x28() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![
            0x38, // SEC
            0xf8, // SED
            0x78, // SEI
            0x08, // PHP
            0x28, // PLP
        ]);
        assert!(cpu.status.is_set(Flags::C));
        assert!(cpu.status.is_set(Flags::D));
        assert!(cpu.status.is_set(Flags::I));
    }
}
