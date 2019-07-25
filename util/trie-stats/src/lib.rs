use hash_db::{HashDB, HashDBRef, Hasher};
use trie_db::{self, DBValue, NodeCodec, TrieDB, TrieError, NibbleSlice};
use trie_db::node::OwnedNode;
use elastic_array::ElasticArray36;
use rlp::{decode, Decodable};
use std::fmt::Debug;
use elastic_array::core_::marker::PhantomData;

/// Empty slice encoded as non-leaf partial key.
///
/// Copy of private trie_db::nibbleslice::EMPTY_ENCODED.
pub const NIBBLESLICE_EMPTY_ENCODED: &[u8] = &[0];

#[derive(Clone, Eq, PartialEq, Debug)]
enum Status {
	Entering,
	At,
	AtChild(usize),
	Exiting,
}

#[derive(Eq, PartialEq, Debug)]
struct Crumb {
	node: OwnedNode,
	status: Status,
}

impl Crumb {
	/// Move on to next status in the node's sequence.
	fn increment(&mut self) {
		self.status = match (&self.status, &self.node) {
			(_, &OwnedNode::Empty) => Status::Exiting,
			(&Status::Entering, _) => Status::At,
			(&Status::At, &OwnedNode::Branch(_)) => Status::AtChild(0),
			(&Status::AtChild(x), &OwnedNode::Branch(_)) if x < 15 => Status::AtChild(x + 1),
			_ => Status::Exiting,
		}
	}
}

#[derive(Debug)]
enum TrieStatsItem<A: Decodable + Debug> {
    Node(usize),  // A Trie node parameterized by its byte size. May include value data.
	// A stored value parameterized by its byte size.
	Value {
		size: usize,
		key: Vec<u8>,
		account: Option<A>,
	},
}

/// Iterator for going through all values in the trie.
struct TrieDBStatsIterator<'a, H: Hasher + 'a, C: NodeCodec<H> + 'a, A: Decodable + Debug> {
	db: &'a TrieDB<'a, H, C>,
	trail: Vec<Crumb>,
	key_nibbles: Vec<u8>,
    node_size: Option<usize>,
	_marker: PhantomData<A>,
}

impl<'a, H: Hasher, C: NodeCodec<H>, A: Decodable + Debug> TrieDBStatsIterator<'a, H, C, A> {
	/// Create a new iterator.
	fn new(db: &'a TrieDB<H, C>) -> trie_db::Result<Self, H::Out, C::Error>
	{
		let mut r = TrieDBStatsIterator {
			db,
			trail: Vec::with_capacity(8),
			key_nibbles: Vec::with_capacity(64),
			node_size: None,
			_marker: Default::default(),
		};
		db.root_data().and_then(|root_data| {
			r.node_size = Some(root_data.len());
			r.descend(&root_data)
		})?;
		Ok(r)
	}

	/// Descend into a payload.
	fn descend(&mut self, d: &[u8]) -> trie_db::Result<(), H::Out, C::Error> {
		let partial_key = self.encoded_key();
		let node_data = get_raw_or_lookup(&self.db, d, &partial_key)?;
		let node = C::decode(&node_data)
			.map_err(|err| {
				let key = C::try_decode_hash(d)
					.expect("try_decode_hash in get_raw_or_lookup succeeded; qed");
				TrieError::DecoderError(key, err)
			})?;

		Ok(self.descend_into_node(node.into()))
	}

	/// Descend into a payload.
	fn descend_into_node(&mut self, node: OwnedNode) {
		self.trail.push(Crumb { status: Status::Entering, node });
		match &self.trail.last().expect("just pushed item; qed").node {
			&OwnedNode::Leaf(ref n, _) | &OwnedNode::Extension(ref n, _) => {
				self.key_nibbles.extend((0..n.len()).map(|i| n.at(i)));
			},
			_ => {}
		}
	}

	/// The present key.
	fn key(&self) -> Vec<u8> {
		// collapse the key_nibbles down to bytes.
		let nibbles = &self.key_nibbles;
		let mut i = 1;
		let mut result = <Vec<u8>>::with_capacity(nibbles.len() / 2);
		let len = nibbles.len();
		while i < len {
			result.push(nibbles[i - 1] * 16 + nibbles[i]);
			i += 2;
		}
		result
	}

	/// Encoded key for storage lookup
	fn encoded_key(&self) -> ElasticArray36<u8> {
		let key = self.key();
		let slice = NibbleSlice::new(&key);
		if self.key_nibbles.len() % 2 == 1 {
			NibbleSlice::new_composed(&slice, &NibbleSlice::new_offset(&self.key_nibbles[(self.key_nibbles.len() - 1)..], 1)).encoded(false)
		} else {
			slice.encoded(false)
		}
	}
}

impl<'a, H: Hasher, C: NodeCodec<H>, A: Decodable + Debug> Iterator for TrieDBStatsIterator<'a, H, C, A> {
	type Item = trie_db::Result<TrieStatsItem<A>, H::Out, C::Error>;

	fn next(&mut self) -> Option<Self::Item> {
		enum IterStep<O, E> {
			Continue,
			PopTrail,
			Descend(trie_db::Result<DBValue, O, E>),
		}
		loop {
			// After descending into a new trie node, yield its size.
			if let Some(node_size) = self.node_size {
				self.node_size = None;
				return Some(Ok(TrieStatsItem::Node(node_size)))
			}

			let iter_step = {
				self.trail.last_mut()?.increment();
				let b = self.trail.last().expect("trail.last_mut().is_some(); qed");

				match (b.status.clone(), &b.node) {
					(Status::Exiting, n) => {
						match *n {
							OwnedNode::Leaf(ref n, _) | OwnedNode::Extension(ref n, _) => {
								let l = self.key_nibbles.len();
								self.key_nibbles.truncate(l - n.len());
							},
							OwnedNode::Branch(_) => { self.key_nibbles.pop(); },
							_ => {}
						}
						IterStep::PopTrail
					},
					(Status::At, &OwnedNode::Branch(ref branch)) if branch.has_value() => {
						let key = {
							let aux_hash = H::hash(&self.key());
							self.db.db().get(&aux_hash, &[])
								.expect("Missing fatdb hash")
								.into_vec()
						};
						let value = branch.get_value().expect("already checked `has_value`");
						return Some(Ok(TrieStatsItem::Value {
							size: value.len(),
							key,
							account: decode(value).ok(),
						}));
					},
					(Status::At, &OwnedNode::Leaf(_, ref v)) => {
						let key = {
							let aux_hash = H::hash(&self.key());
							self.db.db().get(&aux_hash, &[])
								.expect("Missing fatdb hash")
								.into_vec()
						};
						return Some(Ok(TrieStatsItem::Value {
							size: v.len(),
							key,
							account: decode(v).ok(),
						}));
					},
					(Status::At, &OwnedNode::Extension(_, ref d)) => {
						IterStep::Descend::<H::Out, C::Error>(
							get_raw_or_lookup(&self.db, &*d, &self.encoded_key())
						)
					},
					(Status::At, &OwnedNode::Branch(_)) => IterStep::Continue,
					(Status::AtChild(i), &OwnedNode::Branch(ref branch)) if branch.index(i).is_some() => {
						match i {
							0 => self.key_nibbles.push(0),
							i => *self.key_nibbles.last_mut()
								.expect("pushed as 0; moves sequentially; removed afterwards; qed") = i as u8,
						}
                        let child_ref = &branch.index(i)
							.expect("this arm guarded by branch[i].is_some(); qed");
						IterStep::Descend::<H::Out, C::Error>(
							get_raw_or_lookup(&self.db, child_ref, &self.encoded_key())
						)
					},
					(Status::AtChild(i), &OwnedNode::Branch(_)) => {
						if i == 0 {
							self.key_nibbles.push(0);
						}
						IterStep::Continue
					},
					_ => panic!() // Should never see Entering or AtChild without a Branch here.
				}
			};

			match iter_step {
				IterStep::PopTrail => {
					self.trail.pop();
				},
				IterStep::Descend::<H::Out, C::Error>(Ok(d)) => {
					self.node_size = Some(d.len());
					let node = C::decode(&d).expect("encoded data read from db; qed");
					self.descend_into_node(node.into())
				},
				IterStep::Descend::<H::Out, C::Error>(Err(e)) => {
					return Some(Err(e))
				}
				IterStep::Continue => {},
			}
		}
	}
}

/// Given some node-describing data `node`, and node key return the actual node RLP.
/// This could be a simple identity operation in the case that the node is sufficiently small, but
/// may require a database lookup. If `is_root_data` then this is root-data and
/// is known to be literal.
/// `partial_key` is encoded nibble slice that addresses the node.
///
/// Copy of the private method TrieDB::get_raw_or_lookup.
fn get_raw_or_lookup<'db, H, C>(db: &'db TrieDB<'db, H, C>, node: &[u8], partial_key: &[u8])
	-> trie_db::Result<DBValue, H::Out, C::Error>
	where
		H: Hasher,
		C: NodeCodec<H>
{
	match (partial_key == NIBBLESLICE_EMPTY_ENCODED, C::try_decode_hash(node)) {
		(false, Some(key)) => {
			db.db()
				.get(&key, partial_key)
				.ok_or_else(|| Box::new(TrieError::IncompleteDatabase(key)))
		}
		_ => Ok(DBValue::from_slice(node))
	}
}

#[derive(Eq, PartialEq, Debug)]
pub struct TrieStats {
    pub node_count: usize,
	pub node_total_size: usize,
	pub value_count: usize,
	pub value_total_size: usize,
	pub account_count: usize,
	pub child_node_count: usize,
	pub child_node_total_size: usize,
	pub child_value_count: usize,
	pub child_value_total_size: usize,
}

impl Default for TrieStats {
	fn default() -> Self {
		TrieStats {
			node_count: 0,
			node_total_size: 0,
			value_count: 0,
			value_total_size: 0,
			account_count: 0,
			child_node_count: 0,
			child_node_total_size: 0,
			child_value_count: 0,
			child_value_total_size: 0,
		}
	}
}

impl TrieStats {
	fn add<A>(self, item: TrieStatsItem<A>, is_child: bool) -> TrieStats
		where A: Decodable + Debug
	{
		match (item, is_child) {
			(TrieStatsItem::Node(size), false) =>
				TrieStats {
					node_count: self.node_count + 1,
					node_total_size: self.node_total_size + size,
					..self
				},
			(TrieStatsItem::Node(size), true) =>
				TrieStats {
					child_node_count: self.child_node_count + 1,
					child_node_total_size: self.child_node_total_size + size,
					..self
				},
			(TrieStatsItem::Value { size, key: _, account }, false) => {
				let account_indicator = if account.is_some() { 1 } else { 0 };
				TrieStats {
					value_count: self.value_count + 1,
					value_total_size: self.value_total_size + size,
					account_count: self.account_count + account_indicator,
					..self
				}
			}
			(TrieStatsItem::Value { size, key: _, account: _ }, true) => {
				TrieStats {
					child_value_count: self.child_value_count + 1,
					child_value_total_size: self.child_value_total_size + size,
					..self
				}
			}
		}
	}
}

pub fn trie_stats<'db, H, C, A, DB, F>(db: DB, root: &H::Out, f: F)
	-> trie_db::Result<TrieStats, H::Out, C::Error>
	where
		H: Hasher,
		C: NodeCodec<H>,
		A: Decodable + Debug,
		DB: HashDBRef<H, DBValue> + 'db,
		F: Fn(&[u8], &A) -> (Box<dyn HashDB<H, DBValue> + 'db>, H::Out),
{
	let trie = <TrieDB<H, C>>::new(&db, root)?;

	let mut stats = TrieStats::default();
	for item in <TrieDBStatsIterator<_, _, A>>::new(&trie)? {
		let item = item?;

		match item {
			TrieStatsItem::Value { size: _, ref key, account: Some(ref account) } => {
				let (account_db, root) = f(&key, account);
				let account_db_ref = account_db.as_ref();
				let account_trie = <TrieDB<H, C>>::new(&account_db_ref, &root)?;

				for item in <TrieDBStatsIterator<_, _, A>>::new(&account_trie)? {
					stats = stats.add(item?, true);
				}
			}
			_ => {}
		}

		stats = stats.add(item, false);
	}
	Ok(stats)
}

#[cfg(test)]
mod tests {
	use super::{TrieDBStatsIterator, TrieStats};
	use hex_literal::hex;
	use memory_db::{MemoryDB, PrefixedKey};
	use keccak_hasher::KeccakHasher;
	use reference_trie::{RefTrieDB, RefTrieDBMut, RefLookup, Trie, TrieMut, NibbleSlice};
	use trie_db::DBValue;
	use crate::trie_stats;

	#[test]
	fn iterator_works() {
		let pairs = vec![
			(hex!("0103000000000000000464").to_vec(), hex!("fffffffffe").to_vec()),
			(hex!("0103000000000000000469").to_vec(), hex!("ffffffffff").to_vec()),
		];

		let mut memdb = MemoryDB::<KeccakHasher, PrefixedKey<_>, DBValue>::default();
		let mut root = Default::default();
		{
			let mut t = RefTrieDBMut::new(&mut memdb, &mut root);
			for (x, y) in &pairs {
				t.insert(x, y).unwrap();
			}
		}

		let trie = RefTrieDB::new(&memdb, &root).unwrap();

		let iter = TrieDBStatsIterator::new(&trie).unwrap();
		let iter_pairs = iter.collect::<Result<Vec<_>, _>>().unwrap();

//		let expected = vec![];
//		assert_eq!(iter_pairs, expected);

		let expected = TrieStats {
			node_count: 1,
			node_total_size: 32,
			value_count: 2,
			value_total_size: 10,
		};
		assert_eq!(trie_stats(&trie).unwrap(), expected);
	}
}
