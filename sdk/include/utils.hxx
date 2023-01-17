#pragma once

namespace utils
{
   [[ nodiscard ]]
   std::uint8_t* stack_image( const std::string_view image_name )
   {
      for ( const auto& it : std::stacktrace::current( ) )
      {
         if ( it.description( ).find( image_name ) == std::string::npos )
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

            return ptr< std::uint8_t* >( dos_header );
         } while ( image_ptr-- );
      }
      return {};
   }
}
