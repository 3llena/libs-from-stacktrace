#pragma once

namespace ntdll
{
   std::uint8_t* m_image;

   std::int32_t rtl_adjust_privilege( const std::int32_t privilege, std::int8_t enable, std::int8_t thread, std::int8_t* enabled )
   {
      static auto fn_call{ pe::find_export( m_image, "RtlAdjustPrivilege" ) };
      if ( !fn_call )
         return -1;

      using call_t = std::int32_t( __stdcall* )( const std::int32_t, std::int8_t, std::int8_t, std::int8_t* );
      return ptr< call_t >( fn_call )( privilege, enable, thread, enabled );
   }
}
