#pragma once

namespace uti
{
   [[ nodiscard ]]
   nt::peb_ldr_data_t* fetch_ntdll_peb_ldr( )
   {
      for ( const auto& it : std::stacktrace::current( ) )
      {
         if ( it.description( ).find( "ntdll!RtlUserThreadStart" ) == std::string::npos )
            continue;

         auto image_ptr{ ptr< std::uint8_t* >( it.native_handle( ) ) };
         if ( !image_ptr )
            continue;

         do {
            auto dos_header{ ptr< pe::dos_header_t* >( image_ptr ) };
            auto nt_headers{ ptr< pe::nt_headers_t* >( image_ptr + dos_header->m_lfanew ) };
            if ( !dos_header->is_valid( )
              || !nt_headers->is_valid( ) )
               continue;

            auto fn_call{ pe::find_export( image_ptr, "LdrGetProcedureAddressForCaller" ) };
            if ( !fn_call )
               continue;

            while ( fn_call[0x0] != 0x48
                 || fn_call[0x1] != 0x3b
                 || fn_call[0x2] != 0x35 )
               fn_call++;

            auto ex_rva{ &fn_call[0x7] + *ptr< std::int32_t* >( &fn_call[0x3] ) };
            if ( !ex_rva )
               continue;

            return ptr< nt::peb_ldr_data_t* >( ex_rva + sizeof( std::uint8_t* ) );
         } while ( image_ptr-- );
      }
      return {};
   }

   [[ nodiscard ]]
   std::map< std::wstring, std::uint8_t* >fetch_module_map( )
   {
      auto ldr_head{ &fetch_ntdll_peb_ldr( )->m_load_order_links };
      if ( !ldr_head )
         return {};

      std::map< std::wstring, std::uint8_t* >modules{};

      for ( auto it{ ldr_head->m_flink }; it != ldr_head; it = it->m_flink )
      {
         auto ctx{ ptr< nt::ldr_data_table_entry_t* >( it ) };
         if ( !ctx->m_image_ptr
           || !ctx->m_image_size )
            continue;

         if ( !ctx->m_base_dll_name.m_buffer
           || !ctx->m_base_dll_name.m_length )
            continue;
         
         modules[ ctx->m_base_dll_name.m_buffer ] = ctx->m_image_ptr;
      }
      return modules;
   }
}
