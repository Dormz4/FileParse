class Uleb128:
    def __init__(self) -> None:
        super().__init__()


class ClassDataItem:

    def __init__(self, static_fields_size,instance_fields_size,direct_methods_size,virtual_methods_size) -> None:
        super().__init__()
        self.m_static_fields_size = static_fields_size
        self.m_instance_fields_size = instance_fields_size
        self.m_direct_methods_size = direct_methods_size
        self.m_virtual_methods_size = virtual_methods_size
