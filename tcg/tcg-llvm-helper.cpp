#if 0
extern "C" {
#include "qemu/osdep.h"
}

#include "llvm/ADT/StringRef.h"
#include "llvm/ExecutionEngine/JITSymbol.h"
#include "llvm/ExecutionEngine/Orc/CompileOnDemandLayer.h"
#include "llvm/ExecutionEngine/Orc/CompileUtils.h"
#include "llvm/ExecutionEngine/Orc/Core.h"
#include "llvm/ExecutionEngine/Orc/ExecutionUtils.h"
#include "llvm/ExecutionEngine/Orc/IRCompileLayer.h"
#include "llvm/ExecutionEngine/Orc/IRTransformLayer.h"
#include "llvm/ExecutionEngine/Orc/JITTargetMachineBuilder.h"
#include "llvm/ExecutionEngine/Orc/RTDyldObjectLinkingLayer.h"
#include "llvm/ExecutionEngine/Orc/TPCIndirectionUtils.h"
#include "llvm/ExecutionEngine/Orc/TargetProcessControl.h"
#include "llvm/ExecutionEngine/SectionMemoryManager.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/Transforms/InstCombine/InstCombine.h"
#include "llvm/Transforms/Scalar.h"
#include "llvm/Transforms/Scalar/GVN.h"
#include "llvm/ADT/APFloat.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Type.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/TargetSelect.h"
#include "llvm/Target/TargetMachine.h"

using namespace llvm;
using namespace llvm::orc;


class TCGLLVMContext {
private:
    std::unique_ptr<TargetProcessControl> TPC;
    std::unique_ptr<ExecutionSession> ES;
    std::unique_ptr<TPCIndirectionUtils> TPCIU;

    DataLayout DL;
    MangleAndInterner Mangle;

    RTDyldObjectLinkingLayer ObjectLayer;
    IRCompileLayer CompileLayer;
    IRTransformLayer OptimizeLayer;

    static Expected<ThreadSafeModule> optimizeModule(ThreadSafeModule TSM, const MaterializationResponsibility &R);

public:
    TCGLLVMContext(std::unique_ptr<TargetProcessControl> TPC,
                   std::unique_ptr<ExecutionSession> ES,
                   std::unique_ptr<TPCIndirectionUtils> TPCIU,
                   JITTargetMachineBuilder JTMB, DataLayout DL);
};



TCGLLVMContext::TCGLLVMContext(std::unique_ptr<TargetProcessControl> TPC,
                               std::unique_ptr<ExecutionSession> ES,
                               std::unique_ptr<TPCIndirectionUtils> TPCIU,
                               JITTargetMachineBuilder JTMB,
                               DataLayout DL) :
        TPC(std::move(TPC)),
        ES(std::move(ES)),
        TPCIU(std::move(TPCIU)),
        DL(std::move(DL)),
        Mangle(*this->ES, this->DL),
        ObjectLayer(*this->ES, []() { return std::make_unique<SectionMemoryManager>(); }),
        CompileLayer(*this->ES, ObjectLayer, std::make_unique<ConcurrentIRCompiler>(std::move(JTMB))),
        OptimizeLayer(*this->ES, CompileLayer, optimizeModule)
{

}

Expected<ThreadSafeModule> TCGLLVMContext::optimizeModule(ThreadSafeModule TSM, const MaterializationResponsibility &R)
{
    TSM.withModuleDo([](Module &M) {
        // Create a function pass manager.
        auto FPM = std::make_unique<legacy::FunctionPassManager>(&M);

        // Add some optimizations.
        FPM->add(createInstructionCombiningPass());
        FPM->add(createReassociatePass());
        FPM->add(createGVNPass());
        FPM->add(createCFGSimplificationPass());
        FPM->doInitialization();

        // Run the optimizations over all functions in the module being added to
        // the JIT.
        for (auto &F : M) {
            FPM->run(F);
        }
    });

    return std::move(TSM);
}

extern "C" TCGLLVMContext *tcg_llvm_context_alloc(void)
{
    ExitOnError ExitOnErr;
    
    auto SSP = std::make_shared<SymbolStringPool>();
    auto TPC = ExitOnErr(SelfTargetProcessControl::Create(SSP));
    auto ES = std::make_unique<ExecutionSession>(std::move(SSP));
    auto TPCIU = ExitOnErr(TPCIndirectionUtils::Create(*TPC));
    
    /*TPCIU->createLazyCallThroughManager(
        *ES, pointerToJITTargetAddress(&handleLazyCallThroughError));

    ExitOnErr(setUpInProcessLCTMReentryViaTPCIU(*TPCIU));*/

    JITTargetMachineBuilder JTMB(TPC->getTargetTriple());

    auto DL = ExitOnErr(JTMB.getDefaultDataLayoutForTarget());
    
    return new TCGLLVMContext(std::move(TPC),
                              std::move(ES),
                              std::move(TPCIU),
                              std::move(JTMB),
                              std::move(DL));
}
#endif