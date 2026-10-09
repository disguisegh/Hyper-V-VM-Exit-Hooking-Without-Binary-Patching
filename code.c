void set_up_hyperv_hooks(cr3 hyperv_cr3, virtual_address_t entry_point, UINT64 guest_kernel_cr3)
{
    AsmWriteCr3(hyperv_cr3.flags);

    UINT64 hyperv_text_base = find_hyperv_text_base(hyperv_cr3, entry_point);
    UINT64 hyperv_text_end = find_hyperv_text_end(hyperv_cr3, entry_point);
    UINT64 hyperv_text_size = hyperv_text_end - hyperv_text_base;

    if (hyperv_text_base == 0)
        return;

    UINT8* payload_entry_point = NULL;
    if (payload_get_relocated_entry_point(&payload_entry_point) != EFI_SUCCESS || payload_entry_point == NULL)
        return;

    CHAR8* code_ref = NULL;
    UINT8 is_intel = 0;

    EFI_STATUS status = find_bytes(&code_ref, (CHAR8*)hyperv_text_base, hyperv_text_size,
        "\xE8\x00\x00\x00\x00\x48\x89\x04\x24\xE9", "x????xxxxx");

    if (status == EFI_NOT_FOUND)
    {
        status = find_bytes(&code_ref, (CHAR8*)hyperv_text_base, hyperv_text_size,
            "\xE8\x00\x00\x00\x00\xE9\x00\x00\x00\x00\x74\x0D", "x????x????xx");
        is_intel = 1;
    }

    if (status != EFI_SUCCESS)
        return;

    CHAR8* original_vmexit_handler = (code_ref + 5) + *(INT32*)(code_ref + 1);

    UINT8* payload_detour = NULL;
    CHAR8* get_vmcb_gadget = NULL;

    if (is_intel == 0)
    {
        if (find_bytes(&get_vmcb_gadget, (CHAR8*)hyperv_text_base, hyperv_text_size,
                "\x65\x48\x8B\x04\x25\x00\x00\x00\x00\x48\x8B\x88\x00\x00\x00\x00\x48\x8B\x81\x00\x00\x00\x00\x48\x8B",
                "xxxxx????xxx????xxx????xx") != EFI_SUCCESS)
            return;
    }

    if (payload_isa_ok(is_intel) == 0)
        return;

    call_entry(&payload_detour, payload_entry_point, original_vmexit_handler,
        (UINT64)payload_heap_ranges, payload_heap_range_count, uefi_boot_physical_base_address,
        uefi_boot_image_size, guest_kernel_cr3, get_vmcb_gadget);

    if (payload_detour == NULL)
        return;

    CHAR8* code_cave = NULL;
    if (find_bytes(&code_cave, (CHAR8*)hyperv_text_base, hyperv_text_size,
            "\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC", "xxxxxxxxxxxxxxxx") != EFI_SUCCESS)
        return;

    UINT64 call_page_va = (UINT64)code_ref & ~0xFFFull;
    UINT64 cave_page_va = (UINT64)code_cave & ~0xFFFull;

    virtual_address_t call_va = { .address = call_page_va };
    pte_64* call_pte = pte_for(hyperv_cr3, call_va);
    if (call_pte == NULL)
        return;

    UINT8* original_call_page = (UINT8*)(call_pte->page_frame_number << 12);
    UINT8* shadow_call_page = (UINT8*)take_shadow();
    if (shadow_call_page == NULL)
        return;

    mm_copy_memory(shadow_call_page, original_call_page, 0x1000);

    if (bake_hook(&hv_vmexit_hook_data, code_cave, payload_detour) != EFI_SUCCESS)
        return;

    UINT32 new_call_rva = (UINT32)(code_cave - (code_ref + 5));
    UINT64 call_offset = (UINT64)code_ref & 0xFFF;
    mm_copy_memory(shadow_call_page + call_offset + 1, &new_call_rva, sizeof(new_call_rva));

    if (cave_page_va == call_page_va)
    {
        mm_copy_memory(shadow_call_page + ((UINT64)code_cave & 0xFFF), hv_vmexit_hook_data.hook_bytes, 14);
    }
    else
    {
        virtual_address_t cave_va = { .address = cave_page_va };
        pte_64* cave_pte = pte_for(hyperv_cr3, cave_va);
        if (cave_pte == NULL)
            return;

        UINT8* original_cave_page = (UINT8*)(cave_pte->page_frame_number << 12);
        UINT8* shadow_cave_page = (UINT8*)take_shadow();
        if (shadow_cave_page == NULL)
            return;

        mm_copy_memory(shadow_cave_page, original_cave_page, 0x1000);
        mm_copy_memory(shadow_cave_page + ((UINT64)code_cave & 0xFFF), hv_vmexit_hook_data.hook_bytes, 14);

        cave_pte->page_frame_number = (UINT64)shadow_cave_page >> 12;
        __invlpg((void*)cave_page_va);
    }

    call_pte->page_frame_number = (UINT64)shadow_call_page >> 12;
    __invlpg((void*)call_page_va);
}