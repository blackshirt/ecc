import time
import crypto.ecdsa

fn main() {
	iterations := 10000

	pvkey := ecdsa.PrivateKey.new() or { panic(err) }
	println('Benchmarking PrivateKey.new (before patch)...')
	mut total_gen_time := i64(0)
	for _ in 0 .. iterations {
		sw := time.new_stopwatch()

		elapsed := sw.elapsed().microseconds()
		total_gen_time += elapsed
	}
	avg_gen_time := total_gen_time / iterations
	println('Average PrivateKey.new (before patch) time: ${avg_gen_time} µs')
}
