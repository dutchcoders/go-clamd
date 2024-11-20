package clamd

type Builder struct {
	address   string
	chunkSize int
}

func NewBuilder() *Builder {
	return &Builder{
		address:   "",
		chunkSize: CHUNK_SIZE,
	}
}

func (b *Builder) WithAddress(address string) *Builder {
	b.address = address
	return b
}

func (b *Builder) WithChunkSize(chunkSize int) *Builder {
	b.chunkSize = chunkSize
	return b
}

func (b *Builder) Build() *Clamd {
	return &Clamd{
		address:   b.address,
		chunkSize: b.chunkSize,
	}
}
