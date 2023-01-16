#include <iostream>
#include <stacktrace>
#include <map>

template< class type_t >
auto ptr( auto address ) { return ( type_t )address; }

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

   [[ nodiscard ]]
   std::uint8_t* find_export( std::uint8_t* image_ptr, const std::string_view export_name )
   {
      auto dos_header{ ptr< dos_header_t* >( image_ptr ) };
      auto nt_headers{ ptr< nt_headers_t* >( image_ptr + dos_header->m_lfanew ) };
      if ( !dos_header->is_valid( )
        || !nt_headers->is_valid( ) )
         return {};

      auto exp_dir{ ptr< pe::export_directory_t* >( image_ptr + nt_headers->m_export_table.m_virtual_address ) };
      if ( !exp_dir->m_address_of_functions 
        || !exp_dir->m_address_of_names 
        || !exp_dir->m_address_of_names_ordinals )
         return {};

      auto name{ ptr< std::int32_t* >( image_ptr + exp_dir->m_address_of_names ) };
      auto func{ ptr< std::int32_t* >( image_ptr + exp_dir->m_address_of_functions ) };
      auto ords{ ptr< std::int16_t* >( image_ptr + exp_dir->m_address_of_names_ordinals ) };

      std::map< std::string, std::uint8_t* >exports{};

      for ( std::int32_t i{}; i < exp_dir->m_number_of_names; i++ )
      {
         auto cur_name{ image_ptr + name[i] };
         auto cur_func{ image_ptr + func[ords[i]] };
         if ( !cur_name 
           || !cur_func )
            continue;

         if ( export_name == ptr< const char* >( cur_name ) ) 
            return ptr< std::uint8_t* >( cur_func );
      }
      return {};
   }
}

namespace kernel32
{
   [[ nodiscard ]]
   std::uint8_t* find_image( )
   {
      for ( const auto& it : std::stacktrace::current( ) )
      {
         if ( it.description( ).find( "KERNEL32" ) == std::string::npos )
            continue;

         auto image_ptr{ ptr< std::uint8_t* >( it.native_handle( ) ) };
         if ( !image_ptr )
            return {};

         do {
            auto dos_header{ ptr< pe::dos_header_t* >( image_ptr ) };
            auto nt_headers{ ptr< pe::nt_headers_t* >( image_ptr + dos_header->m_lfanew ) };
            if ( !dos_header->is_valid( )
              || !nt_headers->is_valid( ) )
               continue;

            return ptr< std::uint8_t* >( dos_header );
         } while ( image_ptr-- );
      }
      return {};
   }

   [[ nodiscard ]]
   std::uint8_t* load_library( const std::string_view library_name )
   {
      static auto fn_call{ pe::find_export( find_image( ), "LoadLibraryA" ) };
      if ( !fn_call )
         return {};

      using call_t = std::uint8_t*( __stdcall* )( const char* );
      return ptr< call_t >( fn_call )( library_name.data( ) );
   }
}

namespace advapi
{
   // NIGGER
}

std::int32_t main( )
{
   // ;3
}  