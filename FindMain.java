//Finds Main based on libc_start_main function call. Also shows how to pull out values from high pcode.
//
//@author
//@category Analysis
//@keybinding
//@menupath
//@toolbar
import java.util.ArrayList;
import java.util.List;
import java.util.Iterator;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.InvalidInputException;
import ghidra.app.decompiler.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.*;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.pcode.HighFunction;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.data.*;
import ghidra.program.model.pcode.HighFunctionDBUtil;

import ghidra.util.exception.InvalidInputException;

public class FindMain extends GhidraScript {

    @Override
    protected void run() throws Exception {
        Program program = currentProgram;
        FunctionManager functionManager = program.getFunctionManager();
        ReferenceManager referenceManager = program.getReferenceManager();
        
        DecompInterface ifc = setupDecompiler(program);

        // Find main based on function name
        Function libcStartMainFunc = getFunctionByName(functionManager, "__libc_start_main");
        if (libcStartMainFunc == null) {
            println("__libc_start_main function not found in the current program.");
            return;
        }

        // Get handle to address for libc_start_main
        Address libcStartMainAddr = libcStartMainFunc.getEntryPoint();
        println("Searching for calls to __libc_start_main at address: " + libcStartMainAddr);
       
        // Iterate over all references to __libc_start_main and find calling functions
        ReferenceIterator references = referenceManager.getReferencesTo(libcStartMainAddr);
        
        List<Function> callingFunctions = new ArrayList<>();
        while (references.hasNext()) {
            Reference ref = references.next();
            if (ref.getReferenceType().isCall()) {
                Address callAddr = ref.getFromAddress();
                println("Call to __libc_start_main found at: " + callAddr);
                
                Function callingFunction = functionManager.getFunctionContaining(callAddr);
                if (callingFunction != null) {
                    println("In function: " + callingFunction.getName() + " at " + callingFunction.getEntryPoint());
                    callingFunctions.add(callingFunction);
                } else {
                    println("No function containing address: " + callAddr);
                }
            }
        }

        println("Calling functions of libc_start_main:");
        for (Function caller : callingFunctions) {
            println("\t" + caller.getName());
        }

        // Decompile to gain access to parameters
        for (Function function : callingFunctions) {
            println("Decompiling " + function.getName());
            HighFunction highFunction = ifc.decompileFunction(function, 30, monitor).getHighFunction();
            if (highFunction == null) {
                continue;
            }

            Iterator<PcodeOpAST> opiter = highFunction.getPcodeOps();
            while (opiter.hasNext()) {
                PcodeOp pcodeOp = opiter.next();
                // println("Opcode " + pcodeOp.toString());

                if (pcodeOp.getOpcode() == PcodeOp.CALL) {
                    Varnode calledFunction = pcodeOp.getInput(0);
                    Address calledAddress = calledFunction.getAddress();

                    // See if this is call to libc_start_main, we know this function calls it
                    if (calledAddress.equals(libcStartMainFunc.getEntryPoint())) {
                        Varnode firstArg = pcodeOp.getInput(1); // 0th operand is next instruction
                        HighVariable firstArgHigh = firstArg.getHigh();
                        
                        // Check first argument to call opCode
                        if (firstArg != null) {
                            
                            if (firstArg.isAddress()) {
                                // If first argument is hard coded address
                                Address mainAddress = firstArg.getAddress();
                                Function mainFunc = functionManager.getFunctionAt(mainAddress);
                                println("Main address at " + mainAddress);
                                if (mainFunc != null) {
                                    try {
                                        mainFunc.setName("main", SourceType.USER_DEFINED);
                                        updateMainFunctionParameters(ifc, mainFunc);
                                        println("Renamed function at " + mainAddress + " to 'main'");
                                    } catch (InvalidInputException e) {
                                        println("Failed to rename function: " + e.getMessage());
                                    }
                                }
                            } else if (firstArg.isUnique()) {
                                // If first argument is a unique varnode.
                                PcodeOp definingPcodeOp = firstArg.getDef();
                                Varnode mainAddressConst = definingPcodeOp.getInput(1);
                                long value = mainAddressConst.getOffset();
                                // Get the AddressFactory from the current program
                                AddressFactory addressFactory = currentProgram.getAddressFactory();

                                // Create an Address object from the long value
                                Address mainAddress = addressFactory.getDefaultAddressSpace().getAddress(value);
                                Function mainFunc = functionManager.getFunctionAt(mainAddress);

                                // A function exists at this address
                                if (mainFunc != null) {
                                    try {
                                        mainFunc.setName("main", SourceType.USER_DEFINED);
                                        updateMainFunctionParameters(ifc, mainFunc);
                                        println("Renamed function at " + mainAddress + " to 'main'");
                                    } catch (InvalidInputException e) {
                                        println("Failed to rename function: " + e.getMessage());
                                    }
                                }
                            } else {
                                println("Function not found at address: ");
                            }
                        }
                    }
                }
            }
        }

        println("Finished searching for __libc_start_main function calls.");
    }

    private Function getFunctionByName(FunctionManager functionManager, String functionName) {
        boolean FUNCTION_FORWARD = true;

        for (Function func : functionManager.getFunctions​(FUNCTION_FORWARD)) {
            // println("Current Function Name: " + func.getName() + " Looking for " + functionName);
            if (func.getName().equals(functionName)) {
                return func;
            }
        }
        return null;
    }

    private DecompInterface setupDecompiler(Program program) throws DecompileException {
        DecompileOptions options = new DecompileOptions();
		DecompInterface ifc = new DecompInterface();
		ifc.setOptions(options);

		if (!ifc.openProgram(program)) {
			throw new DecompileException("Decompiler",
				"Unable to initialize: " + ifc.getLastMessage());
		}
		ifc.setSimplificationStyle("decompile"); //this gives us HighVar names
        
        return ifc;
    }

    private void updateMainFunctionParameters(DecompInterface ifc, Function mainFunc) {
        try {
            HighFunction highFunction = ifc.decompileFunction(mainFunc, 30, monitor).getHighFunction();
            HighFunctionDBUtil.commitParamsToDatabase(highFunction, true, SourceType.ANALYSIS);
            
            // Get existing parameters
            Parameter[] existingParams = mainFunc.getParameters();
            if (existingParams.length < 2) {
                println("Main function does not have the expected number of parameters.");
                return;
            }
            
            // Update parameter names and types
            DataTypeManager dtm = currentProgram.getDataTypeManager();
            
            // int argc
            DataType intDataType = IntegerDataType.dataType;
            existingParams[0].setDataType(intDataType, SourceType.USER_DEFINED);
            existingParams[0].setName("argc", SourceType.USER_DEFINED);
            
            // char **argv
            DataType charPointerType = PointerDataType.getPointer(CharDataType.dataType, dtm);
            DataType charPointerPointerType = PointerDataType.getPointer(charPointerType, dtm);
            existingParams[1].setDataType(charPointerPointerType, SourceType.USER_DEFINED);
            existingParams[1].setName("argv", SourceType.USER_DEFINED);
            
            println("Updated function parameters for 'main'");
        } catch (Exception e) {
            println("Failed to update function parameters for main: " + e.getMessage());
        }
    }
}
