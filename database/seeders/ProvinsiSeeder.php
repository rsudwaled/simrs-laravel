<?php

namespace Database\Seeders;

use App\Http\Controllers\API\VclaimBPJSController;
use App\Models\Provinsi;
use Illuminate\Database\Console\Seeds\WithoutModelEvents;
use Illuminate\Database\Seeder;

class ProvinsiSeeder extends Seeder
{
    /**
     * Run the database seeds.
     *
     * @return void
     */
    public function run()
    {
        $api = new VclaimBPJSController();
        $provinsis = $api->ref_provinsi();
        foreach ($provinsis->response->list as $data) {
            Provinsi::updateOrCreate([
                'kode' => $data->kode,
                'nama' => $data->nama,
            ]);
        }
    }
}
