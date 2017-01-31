//
// Copyright 2014 International Business Machines
// 
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// 
//     http://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

`timescale 1ns / 1ns

module top (
  output          breakpoint
);

   import "DPI-C" function void tlx_bfm_init( );
   import "DPI-C" function void set_simulation_time(input [0:63] simulationTime);
   import "DPI-C" function void get_simuation_error(inout simulationError);
   import "DPI-C" function void tlx_bfm(
                                         input ha_pclock
                                       );
  
   reg             ha_pclock;
  
 // Integers
  integer         i;
  reg [0:63]      simulationTime ;
  reg             simulationError;
  
initial begin
    ha_pclock <= 0;
    tlx_bfm_init();
end

  // Clock generation

  always begin
    #2 ha_pclock = !ha_pclock;
  end

  always @ ( ha_pclock ) begin
    simulationTime = $time;
    set_simulation_time(simulationTime);
    tlx_bfm( ha_pclock);
  end

  always @ (negedge ha_pclock) begin
    get_simuation_error(simulationError);
  end

  always @ (posedge ha_pclock) begin
    if(simulationError)
      $finish;
  end

endmodule
