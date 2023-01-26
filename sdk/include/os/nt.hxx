#pragma once

namespace nt
{
   enum reg_keys_t : std::uint64_t
   {
      classes_root = 0x80000000,
      current_user = 0x80000001,
      local_machine = 0x80000002
   };

   struct list_entry_t
   {
      list_entry_t* m_flink;
      list_entry_t* m_blink;
   };

   struct unicode_string_t
   {
      std::uint16_t m_length;
      std::uint16_t m_maximum_length;
      wchar_t* m_buffer;
   };

   struct peb_ldr_data_t
   {
      std::uint32_t m_length;
      std::uint8_t m_initialized;
      std::uint8_t* m_handle;
      list_entry_t m_load_order_links;
      list_entry_t m_memory_order_links;
      list_entry_t m_initialization_order_links;
   };

   struct ldr_data_table_entry_t
   {
      list_entry_t m_load_order_links;
      list_entry_t m_memory_order_links;
      list_entry_t m_initialization_order_links;
      std::uint8_t* m_image_ptr;
      std::uint8_t* m_entrypoint;
      std::uint32_t m_image_size;
      unicode_string_t m_full_dll_name;
      unicode_string_t m_base_dll_name;
   };
}
