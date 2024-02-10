#include "entry-point.hpp"

void main_thread(HMODULE dll_module)
{
    PROCESS_MITIGATION_DYNAMIC_CODE_POLICY pm_dynamic_code_policy{};
    pm_dynamic_code_policy.AllowRemoteDowngrade = 0;
    pm_dynamic_code_policy.ProhibitDynamicCode = 1;
    SetProcessMitigationPolicy(ProcessDynamicCodePolicy, 
        &pm_dynamic_code_policy, sizeof(pm_dynamic_code_policy));

    PROCESS_MITIGATION_DEP_POLICY pm_dep_policy{};
    pm_dep_policy.Enable = 1;
    pm_dep_policy.Permanent = 1;
    SetProcessMitigationPolicy(ProcessDEPPolicy, 
        &pm_dep_policy, sizeof(pm_dep_policy));

    PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY pm_control_flow_guard_policy{};
    pm_control_flow_guard_policy.EnableControlFlowGuard = 1;
    pm_control_flow_guard_policy.StrictMode = 1;
    SetProcessMitigationPolicy(ProcessControlFlowGuardPolicy, 
        &pm_control_flow_guard_policy, sizeof(pm_control_flow_guard_policy));

    PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY pm_binary_signature_policy{};
    pm_binary_signature_policy.MicrosoftSignedOnly = 1;
    SetProcessMitigationPolicy(ProcessSignaturePolicy,
        &pm_binary_signature_policy, sizeof(pm_binary_signature_policy));

    FreeLibrary(dll_module);
}

bool __stdcall DllMain(HMODULE dll_module, uintptr_t reason_for_call, void*)
{
    if (reason_for_call == DLL_PROCESS_ATTACH)
    {
        std::thread(main_thread, dll_module).detach();
    }
    return true;
}