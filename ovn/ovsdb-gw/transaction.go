//
// OVSDB schema
package ovsdb

import (
	"github.com/coreos/etcd/clientv3"

	"log"
	"time"
)

func insert(cli, ovsdb_table *table, ovsdb_row *row, uuid-name string) uuid
{
	ops := []clientv3.Op{
		clientv3.OpPut("put-key", "123"),
		clientv3.OpGet("put-key"),
		clientv3.OpPut("put-key", "435"),
		clientv3.OpPut("message", "test"),
	}

	for _, op := range ops {
		if _, err := cli.Do(context.TODO(), op); err != nil {
			log.Fatal(err)
		}
	}
	log.Printf("done")
}
