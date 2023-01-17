#pragma once

namespace advapi32
{
   std::uint8_t* m_image;

   [[ nodiscard ]]
   std::int32_t reg_open_key( std::uint8_t* key, const std::string_view sub_key, std::uint8_t** result )
   {
      static auto fn_call{ pe::find_export( m_image, "RegOpenKeyA" ) };
      if ( !fn_call )
         return -1;

      using call_t = std::int32_t( __stdcall* )( std::uint8_t*, const char*, std::uint8_t** );
      return ptr< call_t >( fn_call )( key, sub_key.data( ), result );
   }

   std::int32_t reg_close_key( std::uint8_t* key )
   {
      static auto fn_call{ pe::find_export( m_image, "RegCloseKey" ) };
      if ( !fn_call )
         return -1;

      using call_t = std::int32_t( __stdcall* )( std::uint8_t* );
      return ptr< call_t >( fn_call )( key );
   }
}
