#[derive(Clone, Debug)]
pub enum Direction {
    Encrypt,
    Decrypt,
}

pub trait Ui {
    fn output(&self, percentage: i32);
}
