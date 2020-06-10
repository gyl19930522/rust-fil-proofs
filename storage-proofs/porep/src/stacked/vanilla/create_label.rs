#[cfg(target_arch = "x86")]
use std::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;

use core_affinity;
use std::sync::{Arc, atomic::{AtomicUsize, AtomicIsize, Ordering}};
use std::thread;
use std::fs::File;
use std::cmp::min;
use sha2raw::Sha256;
use parking_lot::Mutex;
use merkletree::store::DiskStore;
use storage_proofs_core::{
    error::Result,
    hasher::Hasher,
    util::{data_at_node_offset, NODE_SIZE},
};

use super::graph::{StackedBucketGraph, load_parents_from_disk, load_parents_exp_from_disk};

pub fn dual_threads_layer_1_by_gyl<H: Hasher>(
    g_size: usize,
    replica_id: &H::Domain,
    layer_labels_ptr: &Arc<Mutex<Vec<u8>>>,
) {
    info!("generating layer: 1");

    let replica_id_ptr = Arc::new(replica_id.clone());

    let layer_labels_ptr_1 = layer_labels_ptr.clone();
    let layer_labels_ptr_2 = layer_labels_ptr_1.clone();
    let layer_labels_ptr_3 = layer_labels_ptr_2.clone();

    let base_parents_addr_1 = Arc::new(Mutex::new([0usize; 6]));
    let base_parents_addr_2 = base_parents_addr_1.clone();

    // sync atom
    let pending_node_1 = Arc::new(AtomicUsize::new(1));
    let pending_node_2 = pending_node_1.clone();
    let finish_node_1 = Arc::new(AtomicIsize::new(-1));
    let finish_node_2 = finish_node_1.clone();

    // thread for sha256
    let t1 = thread::spawn(move || {
        core_affinity::set_for_current(core_affinity::CoreId{id: num_cpus::get() - 1});

        let mut layer_labels_local = layer_labels_ptr_1.lock();
        let base_parents_addr_local = base_parents_addr_1.lock();

        let mut hasher = Sha256::new();

        for node in 0..g_size {
            while pending_node_1.load(Ordering::SeqCst) < node + 1 {};
            hasher.reset();
            let mut buffer = [0u8; 32];
            buffer[..4].copy_from_slice(&1u32.to_be_bytes());
            hasher.input(&[AsRef::<[u8]>::as_ref(replica_id_ptr.as_ref()), &buffer[..]]);

            let start = node * NODE_SIZE;
            let end = start + NODE_SIZE;

            if node > 0 {
                unsafe {
                    let ps = [
                        std::slice::from_raw_parts(base_parents_addr_local[0] as *const u8, NODE_SIZE),
                        std::slice::from_raw_parts(base_parents_addr_local[1] as *const u8, NODE_SIZE),
                        std::slice::from_raw_parts(base_parents_addr_local[2] as *const u8, NODE_SIZE),
                        std::slice::from_raw_parts(base_parents_addr_local[3] as *const u8, NODE_SIZE),
                        std::slice::from_raw_parts(base_parents_addr_local[4] as *const u8, NODE_SIZE),
                        std::slice::from_raw_parts(base_parents_addr_local[5] as *const u8, NODE_SIZE),
                    ];
                    hasher.input(&ps);
                    hasher.input(&ps);
                    hasher.input(&ps);
                    hasher.input(&ps);
                    hasher.input(&ps);
                    hasher.input(&ps);
                    hasher.finish_with_into_by_gyl(ps[0], layer_labels_local[start..end].as_mut());
                }                  
            } else {
                hasher.finish_into_by_gyl(layer_labels_local[0..NODE_SIZE].as_mut());
            }

            layer_labels_local[end - 1] &= 0b0011_1111;
            finish_node_1.store(node as isize, Ordering::SeqCst);
        }
    });

    // thread for loading data
    let t2 = thread::spawn(move || {
        core_affinity::set_for_current(core_affinity::CoreId{id: num_cpus::get() / 2 - 1});
        let layer_labels_local = layer_labels_ptr_2.lock();
        let mut base_parents_addr_local = base_parents_addr_2.lock();
        let file = File::open("/home/parents_nodes.dat").unwrap();
        let mut cache_parents = [0u8; 6 * 4];

        for node in 0..g_size {
            while finish_node_2.load(Ordering::SeqCst) < node as isize {};
            load_parents_from_disk(
                min(node + 1, g_size - 1), 
                &mut cache_parents,
                layer_labels_local.as_ref(), 
                base_parents_addr_local.as_mut(), 
                &file
            );
            
            pending_node_2.store(node + 1, Ordering::SeqCst);
        }
    });

    t1.join().ok();
    t2.join().ok();
}

pub fn dual_threads_layer_n_by_gyl<H: Hasher>(
    layer: usize,
    layers: usize,
    g_size: usize,
    replica_id: &H::Domain,
    layer_labels_ptr: &Arc<Mutex<Vec<u8>>>,
    store: &DiskStore<H::Domain>,
) {
    info!("generating layer: {}", layer);

    let replica_id_ptr = Arc::new(replica_id.clone());

    let layer_labels_ptr_1 = layer_labels_ptr.clone();
    let layer_labels_ptr_2 = layer_labels_ptr_1.clone();
    let layer_labels_ptr_3 = layer_labels_ptr_2.clone();

    let store_ptr = Arc::new(store.clone());

    let base_parents_addr_1 = Arc::new(Mutex::new([0usize; 6]));
    let base_parents_addr_2 = base_parents_addr_1.clone();

    // store exp parentship
    let exp_labels_ptr_1 = Arc::new(Mutex::new([[0u8; NODE_SIZE]; 8]));
    let exp_labels_ptr_2 = exp_labels_ptr_1.clone();

    // sync atom
    let pending_node_1 = Arc::new(AtomicUsize::new(1));
    let pending_node_2 = pending_node_1.clone();
    let finish_node_1 = Arc::new(AtomicIsize::new(-1));
    let finish_node_2 = finish_node_1.clone();

    let t1 = thread::spawn(move || {
        core_affinity::set_for_current(core_affinity::CoreId{id: num_cpus::get() - 1});
        let mut hasher = Sha256::new();

        let mut layer_labels_local = layer_labels_ptr_1.lock();
        let base_parents_addr_local = base_parents_addr_1.lock();
        let exp_labels_local = exp_labels_ptr_1.lock();
        
        for node in 0..g_size {
            while pending_node_1.load(Ordering::SeqCst) < node + 1 {};
            hasher.reset();
            let mut buffer = [0u8; 32];
            // copy once is ok
            buffer[..4].copy_from_slice(&(layer as u32).to_be_bytes());
            buffer[4..12].copy_from_slice(&(node as u64).to_be_bytes());
            hasher.input(&[AsRef::<[u8]>::as_ref(replica_id_ptr.as_ref()), &buffer[..]][..]);
            let start = node * NODE_SIZE;
            let end = start + NODE_SIZE;

            if node > 0 {
                unsafe {
                    let ps = [
                        std::slice::from_raw_parts(base_parents_addr_local[0] as *const u8, NODE_SIZE),
                        std::slice::from_raw_parts(base_parents_addr_local[1] as *const u8, NODE_SIZE),
                        std::slice::from_raw_parts(base_parents_addr_local[2] as *const u8, NODE_SIZE),
                        std::slice::from_raw_parts(base_parents_addr_local[3] as *const u8, NODE_SIZE),
                        std::slice::from_raw_parts(base_parents_addr_local[4] as *const u8, NODE_SIZE),
                        std::slice::from_raw_parts(base_parents_addr_local[5] as *const u8, NODE_SIZE),
                        &(exp_labels_local[0]),
                        &(exp_labels_local[1]),
                        &(exp_labels_local[2]),
                        &(exp_labels_local[3]),
                        &(exp_labels_local[4]),
                        &(exp_labels_local[5]),
                        &(exp_labels_local[6]),
                        &(exp_labels_local[7]),
                    ];
                    hasher.input(&ps);
                    hasher.input(&ps);
                    hasher.input(&ps[..8]);
                    hasher.finish_with_into_by_gyl(ps[8], layer_labels_local[start..end].as_mut());
                }
            } else {
                hasher.finish_into_by_gyl(layer_labels_local[0..NODE_SIZE].as_mut());
            }

            layer_labels_local[end - 1] &= 0b0011_1111;
            finish_node_1.store(node as isize, Ordering::SeqCst);
        }
    });

    let t2 = thread::spawn(move || {
        core_affinity::set_for_current(core_affinity::CoreId{id: num_cpus::get() / 2 - 1});
        let layer_labels_local = layer_labels_ptr_2.lock();
        let mut base_parents_addr_local = base_parents_addr_2.lock();
        let mut exp_labels_local = exp_labels_ptr_2.lock();

        let relation_file = File::open("/home/parents_nodes.dat").unwrap();

        let mut cache_all_parents = [0u8; 14 * 4];

        for node in 0..g_size {
            while finish_node_2.load(Ordering::SeqCst) < node as isize {};
            load_parents_exp_from_disk(
                min(node + 1, g_size - 1), 
                &mut cache_all_parents,
                layer_labels_local.as_ref(),
                exp_labels_local.as_mut(),
                base_parents_addr_local.as_mut(),
                &relation_file,
                store_ptr.as_ref(),
            );

            pending_node_2.store(node + 1, Ordering::SeqCst);
        }
    });

    t1.join().ok();
    t2.join().ok();
}

pub fn create_label<H: Hasher>(
    graph: &StackedBucketGraph<H>,
    replica_id: &H::Domain,
    layer_labels: &mut [u8],
    layer_index: usize,
    node: usize,
) -> Result<()> {
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 32];

    buffer[..4].copy_from_slice(&(layer_index as u32).to_be_bytes());
    buffer[4..12].copy_from_slice(&(node as u64).to_be_bytes());
    hasher.input(&[AsRef::<[u8]>::as_ref(replica_id), &buffer[..]][..]);

    // hash parents for all non 0 nodes
    let hash = if node > 0 {
        // prefetch previous node, which is always a parent
        let prev = &layer_labels[(node - 1) * NODE_SIZE..node * NODE_SIZE];
        unsafe {
            _mm_prefetch(prev.as_ptr() as *const i8, _MM_HINT_T0);
        }

        graph.copy_parents_data(node as u32, &*layer_labels, hasher)
    } else {
        hasher.finish()
    };

    // store the newly generated key
    let start = data_at_node_offset(node);
    let end = start + NODE_SIZE;
    layer_labels[start..end].copy_from_slice(&hash[..]);

    // strip last two bits, to ensure result is in Fr.
    layer_labels[end - 1] &= 0b0011_1111;

    Ok(())
}

pub fn create_label_exp<H: Hasher>(
    graph: &StackedBucketGraph<H>,
    replica_id: &H::Domain,
    exp_parents_data: &[u8],
    layer_labels: &mut [u8],
    layer_index: usize,
    node: usize,
) -> Result<()> {
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 32];

    buffer[0..4].copy_from_slice(&(layer_index as u32).to_be_bytes());
    buffer[4..12].copy_from_slice(&(node as u64).to_be_bytes());
    hasher.input(&[AsRef::<[u8]>::as_ref(replica_id), &buffer[..]][..]);

    // hash parents for all non 0 nodes
    let hash = if node > 0 {
        // prefetch previous node, which is always a parent
        let prev = &layer_labels[(node - 1) * NODE_SIZE..node * NODE_SIZE];
        unsafe {
            _mm_prefetch(prev.as_ptr() as *const i8, _MM_HINT_T0);
        }

        graph.copy_parents_data_exp(node as u32, &*layer_labels, exp_parents_data, hasher)
    } else {
        hasher.finish()
    };

    // store the newly generated key
    let start = data_at_node_offset(node);
    let end = start + NODE_SIZE;
    layer_labels[start..end].copy_from_slice(&hash[..]);

    // strip last two bits, to ensure result is in Fr.
    layer_labels[end - 1] &= 0b0011_1111;

    Ok(())
}
