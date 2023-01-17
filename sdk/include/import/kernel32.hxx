#pragma once

namespace kernel32
{
   std::uint8_t* m_image;

   [[ nodiscard ]]
   std::uint8_t* load_library( const std::string_view library_name )
   {
      static auto fn_call{ pe::find_export( m_image, "LoadLibraryA" ) };
      if ( !fn_call )
         return {};

      using call_t = std::uint8_t*( __stdcall* )( const char* );
      return ptr< call_t >( fn_call )( library_name.data( ) );
   }
}
