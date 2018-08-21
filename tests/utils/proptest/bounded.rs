use proptest::prelude::Just;
use proptest::strategy::{BoxedStrategy, NewTree, Strategy, ValueTree};
use proptest::test_runner::TestRunner;
use std::convert::From;
use std::fmt::Debug;
use std::ops::{Range, RangeInclusive};

pub trait Bounded {
    type Bound;
    fn max(&self) -> Self::Bound;
    fn min(&self) -> Self::Bound;
}

impl Bounded for Range<usize> {
    type Bound = usize;

    fn max(&self) -> usize {
        self.end - 1
    }

    fn min(&self) -> usize {
        self.start
    }
}

impl Bounded for RangeInclusive<usize> {
    type Bound = usize;

    fn max(&self) -> usize {
        *self.end()
    }

    fn min(&self) -> usize {
        *self.start()
    }
}

impl Bounded for Range<f64> {
    type Bound = f64;

    fn max(&self) -> f64 {
        self.end
    }

    fn min(&self) -> f64 {
        self.start
    }
}

impl Bounded for RangeInclusive<f64> {
    type Bound = f64;

    fn max(&self) -> f64 {
        *self.end()
    }

    fn min(&self) -> f64 {
        *self.start()
    }
}

impl<T: Clone + Debug> Bounded for Just<T> {
    type Bound = T;

    fn max(&self) -> T {
        self.0.clone()
    }

    fn min(&self) -> T {
        self.0.clone()
    }
}

#[derive(Debug)]
pub struct BoundedBoxedStrategy<T: Debug> {
    strategy: BoxedStrategy<T>,
    min: T,
    max: T,
}

impl<T: Debug> Strategy for BoundedBoxedStrategy<T> {
    type Value = T;
    type Tree = Box<ValueTree<Value = T>>;

    fn new_tree(&self, runner: &mut TestRunner) -> NewTree<Self> {
        self.strategy.new_tree(runner)
    }

    fn boxed(self) -> BoxedStrategy<T> {
        self.strategy
    }
}

// Deliberately not implemented as Bounded, or the implementation of From would conflict with the
// blanket impl From<T> for T
impl<T: Clone + Debug> BoundedBoxedStrategy<T> {
    pub fn min(&self) -> T {
        self.min.clone()
    }

    pub fn max(&self) -> T {
        self.max.clone()
    }
}

impl<S, T> From<S> for BoundedBoxedStrategy<T>
where
    T: Debug + Clone,
    S: Strategy<Value = T> + Bounded<Bound = T> + 'static,
{
    fn from(arg: S) -> BoundedBoxedStrategy<T> {
        let min = arg.min();
        let max = arg.max();
        BoundedBoxedStrategy {
            strategy: arg.boxed(),
            min,
            max,
        }
    }
}
