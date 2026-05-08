#include "state.h"

DwarfState::DwarfState() : next(nullptr), cfaRegister(0), cfaOffset(0),
    cfaExpression(0), cfaExpressionLength(0) {

}

DwarfState::DwarfState(const DwarfState &other)
    : next(other.next),
    cfaRegister(other.cfaRegister), cfaOffset(other.cfaOffset),
    cfaExpression(other.cfaExpression),
    cfaExpressionLength(other.cfaExpressionLength) {
        
    // Copy the registers array element by element
    for (int i = 0; i < NUM_REGISTERS; ++i) {
        registers[i] = other.registers[i];
    }
}
