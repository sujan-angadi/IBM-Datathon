# LEAKLOCK Hardware Subsystem (`leaklock_controller.v`)

> **Phase 1 Status:** Directory structure and interface specification only. No Verilog RTL is implemented in Phase 1, and no EDA tools are required to run the Streamlit application.

## 1. Purpose
In Phase 3, LEAKLOCK will introduce a deterministic hardware policy decision module named `leaklock_controller.v`. Its role is to receive compact risk metadata produced by the Python scanner alongside active policy configuration registers, and output an immediate enforcement decision (`ALLOW`, `REDACT`, or `BLOCK`).

## 2. Directory Layout
- `rtl/` — Future synthesizable Verilog source files (`leaklock_controller.v`).
- `tb/` — Future Verilog testbenches (`tb_leaklock_controller.v`).
- `sim/` — Future Icarus Verilog (`iverilog` / `vvp`) simulation scripts and waveform outputs (`.vcd` / `.gtkw`).
- `synthesis/` — Future Yosys synthesis scripts and gate-level netlists.
- `physical/` — Future floorplanning, timing, or FPGA constraint files.
- `interface/` — Future Python-to-simulator / Python-to-FPGA bridge adapters.

## 3. Planned Signal Interface (`leaklock_controller.v`)
| Signal | Direction | Width | Description |
| :--- | :--- | :--- | :--- |
| `clk` | Input | 1-bit | System clock |
| `rst_n` | Input | 1-bit | Active-low synchronous reset |
| `valid_in` | Input | 1-bit | Asserted when `risk_vector` and `policy_cfg` are valid |
| `risk_vector` | Input | 8-bit | Bitmask of detected risk categories |
| `policy_cfg` | Input | 6-bit | Policy configuration register mapping risk tiers to actions |
| `valid_out` | Output | 1-bit | Asserted when `decision_out` is valid |
| `decision_out` | Output | 2-bit | Enforcement opcode: `2'b00` = `ALLOW`, `2'b01` = `REDACT`, `2'b10` = `BLOCK` |

## 4. Python Integration & Software Fallback
1. **Software Fallback Mode (Default):** Pure Python evaluates `risk_vector` and `policy_cfg` using identical truth-table logic.
2. **Simulator Bridge Mode (Phase 3):** Python passes test vectors to compiled Icarus Verilog (`vvp`) simulation binaries via `hardware/interface/`.
3. **FPGA Mode (Future Extension):** Python communicates over UART/AXI/PCIe to a physical target without changing the Streamlit UI.
