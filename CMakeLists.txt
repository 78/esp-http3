# ESP32 QUIC/HTTP3 Client Component
# Based on RFC 9000 (QUIC), RFC 9001 (QUIC-TLS), RFC 9114 (HTTP/3)

set(COMPONENT_SRCS
    # QUIC core
    "src/quic/quic_varint.cc"
    "src/quic/quic_types.cc"
    "src/quic/quic_crypto.cc"
    "src/quic/quic_aead.cc"
    "src/quic/quic_frame.cc"
    "src/quic/quic_packet.cc"
    
    # TLS 1.3
    "src/tls/tls_handshake.cc"
    
    # HTTP/3
    "src/h3/h3_frame.cc"
    "src/h3/h3_handler.cc"
    
    # QUIC core components
    "src/core/ack_manager.cc"
    "src/core/flow_controller.cc"
    "src/core/loss_detector.cc"
    "src/core/crypto_manager.cc"
    "src/core/frame_processor.cc"
    "src/core/quic_connection.cc"
    
    # High-level client API
    "src/client/http3_client.cc"
)

set(COMPONENT_INCLUDE_DIRS
    "include"
)

set(COMPONENT_REQUIRES
    mbedtls
    esp_timer
    freertos
    lwip
    esp_psram
)

idf_component_register(
    SRCS ${COMPONENT_SRCS}
    INCLUDE_DIRS ${COMPONENT_INCLUDE_DIRS}
    REQUIRES ${COMPONENT_REQUIRES}
)

# Enable C++17
target_compile_features(${COMPONENT_LIB} PUBLIC cxx_std_17)

# Compiler options
target_compile_options(${COMPONENT_LIB} PRIVATE
    -Wall
    -Wextra
    -Wno-unused-parameter
    -fno-exceptions
)
