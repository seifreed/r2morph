class ReverseShuffle:
    """Deterministically reverse a shuffle input for relocation tests."""

    def shuffle[T](self, values: list[T]) -> None:
        values.reverse()
