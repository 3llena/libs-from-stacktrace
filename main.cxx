#include <iostream>
#include <stacktrace>
#include <map>

namespace pe
{
   enum pe_magic_t
   {
      dos_header = 0x5a4d,
      nt_headers = 0x4550,
      opt_header = 0x020b
   };

   struct dos_header_t
   {
      std::int16_t m_magic;
      std::int16_t m_cblp;
      std::int16_t m_cp;
      std::int16_t m_crlc;
      std::int16_t m_cparhdr;
      std::int16_t m_minalloc;
      std::int16_t m_maxalloc;  
      std::int16_t m_ss;
      std::int16_t m_sp;
      std::int16_t m_csum;
      std::int16_t m_ip;
      std::int16_t m_cs;
      std::int16_t m_lfarlc;
      std::int16_t m_ovno;
      std::int16_t m_res0[0x4];  
      std::int16_t m_oemid;
      std::int16_t m_oeminfo;
      std::int16_t m_res1[0xa];
      std::int16_t m_lfanew;

      [[ nodiscard ]]
      constexpr bool is_valid( )
      {
         return m_magic == pe_magic_t::dos_header;
      }
   };

   struct nt_headers_t 
   {
      struct data_directory_t
      {
         std::int32_t m_virtual_address;
         std::int32_t m_size;
      };

      std::int32_t m_signature;
      std::int16_t m_machine;
      std::int16_t m_number_of_sections;
      std::int32_t m_time_date_stamp;
      std::int32_t m_pointer_to_symbol_table;
      std::int32_t m_number_of_symbols;
      std::int16_t m_size_of_optional_header;
      std::int16_t m_characteristics;

      std::int16_t m_magic;
      std::int8_t m_major_linker_version;
      std::int8_t m_minor_linker_version;
      std::int32_t m_size_of_code;
      std::int32_t m_size_of_initialized_data;
      std::int32_t m_size_of_uninitialized_data;
      std::int32_t m_address_of_entry_point;
      std::int32_t m_base_of_code;
      std::uint64_t m_image_base;
      std::int32_t m_section_alignment;
      std::int32_t m_file_alignment;
      std::int16_t m_major_operating_system_version;
      std::int16_t m_minor_operating_system_version;
      std::int16_t m_major_image_version;
      std::int16_t m_minor_image_version;
      std::int16_t m_major_subsystem_version;
      std::int16_t m_minor_subsystem_version;
      std::int32_t m_win32_version_value;
      std::int32_t m_size_of_image;
      std::int32_t m_size_of_headers;
      std::int32_t m_check_sum;
      std::int16_t m_subsystem;
      std::int16_t m_dll_characteristics;
      std::uint64_t m_size_of_stack_reserve;
      std::uint64_t m_size_of_stack_commit;
      std::uint64_t m_size_of_heap_reserve;
      std::uint64_t m_size_of_heap_commit;
      std::int32_t m_loader_flags;
      std::int32_t m_number_of_rva_and_sizes;

      data_directory_t m_export_table;
      data_directory_t m_import_table;
      data_directory_t m_resource_table;
      data_directory_t m_exception_table;
      data_directory_t m_certificate_table;
      data_directory_t m_base_relocation_table;
      data_directory_t m_debug;
      data_directory_t m_architecture;
      data_directory_t m_global_ptr;
      data_directory_t m_tls_table;
      data_directory_t m_load_config_table;
      data_directory_t m_bound_import;
      data_directory_t m_iat;
      data_directory_t m_delay_import_descriptor;
      data_directory_t m_clr_runtime_header;
      data_directory_t m_reserved;

      [[ nodiscard ]]
      constexpr bool is_valid( ) 
      {
         return m_signature == pe_magic_t::nt_headers 
                 && m_magic == pe_magic_t::opt_header;
      }
   };

   struct export_directory_t 
   {
      std::int32_t m_characteristics;
      std::int32_t m_time_date_stamp;
      std::int16_t m_major_version;
      std::int16_t m_minor_version;
      std::int32_t m_name;
      std::int32_t m_base;
      std::int32_t m_number_of_functions;
      std::int32_t m_number_of_names;
      std::int32_t m_address_of_functions;
      std::int32_t m_address_of_names;
      std::int32_t m_address_of_names_ordinals;
   };

   struct section_header_t
   {
      char m_name[0x8];
      union
      {
         std::int32_t m_physical_address;
         std::int32_t m_virtual_size;
      };
      std::int32_t m_virtual_address;
      std::int32_t m_size_of_raw_data;
      std::int32_t m_pointer_to_raw_data;
      std::int32_t m_pointer_to_relocations;
      std::int32_t m_pointer_to_line_numbers;
      std::int16_t m_number_of_relocations;
      std::int16_t m_number_of_line_numbers;
      std::int32_t m_characteristics;
   };
}

namespace nt
{
   struct unicode_string_t
   {
      std::uint16_t m_length;
      std::uint16_t m_maximum_length;
      wchar_t* m_buffer;
   };

   struct object_attributes_t
   {
      std::uint32_t m_length;
      std::int16_t m_res1[0x2];
      std::uint8_t* m_root_directory;
      unicode_string_t* m_object_name;
      std::uint32_t m_attributes;
      std::int16_t m_res2[0x2];
      std::uint8_t* m_security_descriptor;
      std::uint8_t* m_security_quality_of_service;
   };
}

namespace ntdll
{
   [[ nodiscard ]]
   std::tuple< pe::dos_header_t*, pe::nt_headers_t*, std::uint8_t* >find_image( )
   {
      for ( const auto& it : std::stacktrace::current( ) )
      {
         if ( it.description( ).find( "ntdll!RtlUserThreadStart" ) == std::string::npos )
            continue;

         auto image_ptr{ ( std::uint8_t* )( it.native_handle( ) ) };
         if ( !image_ptr )
            return {};

         do {
            auto dos_header{ ( pe::dos_header_t* )( image_ptr ) };
            auto nt_headers{ ( pe::nt_headers_t* )( image_ptr + dos_header->m_lfanew ) };
            if ( !dos_header->is_valid( )
              || !nt_headers->is_valid( ) )
               continue;

            return std::tuple{ dos_header, nt_headers, ( std::uint8_t* )( dos_header ) };
         } while ( image_ptr-- );
      }
      return {};
   }

   [[ nodiscard ]]
   std::uint8_t* find_export( const std::string_view export_name )
   {
      auto [dos_header, nt_headers, image_ptr] = find_image( );
      if ( !dos_header->is_valid( )
        || !nt_headers->is_valid( ) )
         return {};

      auto exp_dir{ ( pe::export_directory_t* )( image_ptr + nt_headers->m_export_table.m_virtual_address ) };
      if ( !exp_dir->m_address_of_functions 
        || !exp_dir->m_address_of_names 
        || !exp_dir->m_address_of_names_ordinals )
         return {};

      auto name{ ( std::int32_t* )( image_ptr + exp_dir->m_address_of_names ) };
      auto func{ ( std::int32_t* )( image_ptr + exp_dir->m_address_of_functions ) };
      auto ords{ ( std::int16_t* )( image_ptr + exp_dir->m_address_of_names_ordinals ) };

      std::map< std::string, std::uint8_t* >exports{};

      for ( std::int32_t i{}; i < exp_dir->m_number_of_names; i++ )
      {
         auto cur_name{ image_ptr + name[i] };
         auto cur_func{ image_ptr + func[ords[i]] };
         if ( !cur_name 
           || !cur_func )
            continue;

         if ( export_name == ( const char* )( cur_name ) ) return ( std::uint8_t* )( cur_func );
      }
      return {};
   }

   using rtl_init_unicode_string_t = void( __stdcall* )( nt::unicode_string_t*, const wchar_t* );
   using rtl_adjust_privilege_t = std::int32_t( __stdcall* )( std::uint32_t, std::int8_t, std::int8_t, std::int8_t* );
   
   std::int32_t rtl_adjust_privilege( std::uint32_t privilege, std::int8_t enable, std::int8_t current_thread, std::int8_t* enabled ) { return ( ( rtl_adjust_privilege_t )( find_export( "RtlAdjustPrivilege" ) ) )( privilege, enable, current_thread, enabled ); }
   void rtl_init_unicode_string( nt::unicode_string_t* dst_string, const wchar_t* src_string ) { ( ( rtl_init_unicode_string_t )( find_export( "RtlInitUnicodeString" ) ) )( dst_string, src_string ); }
   
   using zw_open_key_t = std::int32_t( __stdcall* )( std::uint8_t**, std::uint32_t, nt::object_attributes_t* );
   using zw_create_key_t = std::int32_t( __stdcall* )( std::uint8_t**, std::uint32_t, nt::object_attributes_t*, std::uint32_t, nt::unicode_string_t*, std::uint32_t, std::uint32_t* );
   using zw_delete_key_t = std::int32_t( __stdcall* )( std::uint8_t* );

   std::int32_t zw_open_key( std::uint8_t** key_handle, std::uint32_t desired_access, nt::object_attributes_t* object_attributes ) { return ( ( zw_open_key_t )( find_export( "ZwOpenKey" ) ) )( key_handle, desired_access, object_attributes ); }
   std::int32_t zw_create_key( std::uint8_t** key_handle, std::uint32_t desired_access, nt::object_attributes_t* object_attributes, std::uint32_t title_index, nt::unicode_string_t* obj_class, std::uint32_t create_options, std::uint32_t* disposition ) { return ( ( zw_create_key_t )( find_export( "ZwCreateKey" ) ) )( key_handle, desired_access, object_attributes, title_index, obj_class, create_options, disposition ); }
   std::int32_t zw_delete_key( std::uint8_t* key_handle ) { return ( ( zw_delete_key_t )( find_export( "ZwOpenKey" ) ) )( key_handle ); }
}

std::int32_t main( )
{
   std::cin.get( );
}  