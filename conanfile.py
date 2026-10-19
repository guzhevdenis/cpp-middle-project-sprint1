from conan import ConanFile
from conan.tools.cmake import CMake, CMakeToolchain, CMakeDeps
from conan.tools.files import copy, rmdir
from conan.tools.layout import basic_layout
import os

class CryptoGuardConan(ConanFile):
    name = "crypto_guard"
    version = "1.0.0"
    settings = "os", "compiler", "build_type", "arch"
    
    def requirements(self):
        self.requires("openssl/3.1.1")
        self.requires("boost/1.83.0")
        self.requires("gtest/1.13.0")
        self.tool_requires("cmake/3.30.0")
    
    def layout(self):
        basic_layout(self, src_folder=".", build_folder="build")
    
    def generate(self):
        deps = CMakeDeps(self)
        deps.generate()
        
        tc = CMakeToolchain(self)
        tc.generate()
    
    def build(self):
        cmake = CMake(self)
        cmake.configure()
        cmake.build()
